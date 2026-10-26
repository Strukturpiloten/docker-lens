"""Actual anonymous descriptor IPC and bounded watchdog controls, never sudo/native."""

import array
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import native_pids_boundary as b
import native_pids_locator as l

SPEC = importlib.util.spec_from_file_location("pids_supervisor", Path(__file__).resolve().parents[1] / "scripts/native-pids-supervisor.py")
s = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(s)


def frame(value):
    body = json.dumps(value, separators=(",", ":")).encode()
    return struct.pack("!I", len(body)) + body


class ChannelTests(unittest.TestCase):
    def setUp(self):
        self.parent, self.child = socket.socketpair()
        self.peer = s.peer_socket(self.child)
        self.budget = b.Budget(time.monotonic_ns() + 180_000_000_000)
        self.channel = s.Channel(self.child, self.budget, self.peer[3])

    def tearDown(self):
        self.parent.close()
        self.child.close()
        os.close(self.peer[3])

    def send_rights(self, body, fds):
        return self.parent.sendmsg([body], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))])

    def test_actual_unnamed_pair_credentials_pidfd_and_cloexec(self):
        self.assertEqual(self.peer[:3], (os.getpid(), os.getuid(), os.getgid()))
        self.assertFalse(os.get_inheritable(self.peer[3]))
        l.live(self.peer[3])

    def test_split_bootstrap_one_capture_fd_ready_and_framed_request(self):
        with tempfile.TemporaryDirectory(prefix="dl-pids-capture-") as directory:
            os.chmod(directory, 0o700)
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                self.send_rights(b"B", [fd])
                self.parent.sendall(b"FPIDS1\n")
                received = self.channel.bootstrap(os.getuid())
                try:
                    self.assertEqual(b.identity(received), b.identity(fd))
                    self.assertEqual(self.parent.recv(8), b"BFREADY\n")
                    self.assertFalse(os.get_inheritable(received))
                    self.parent.sendall(frame({"version": 1, "sequence": 1, "op": "LocateBatch"}))
                    self.assertEqual(self.channel.request(), {"version": 1, "sequence": 1, "op": "LocateBatch"})
                finally:
                    os.close(received)
            finally:
                os.close(fd)

    def test_all_delivered_rights_close_on_extraneous_and_truncated_bootstrap(self):
        for count in (2, 4):
            with self.subTest(count=count), tempfile.TemporaryDirectory() as directory:
                fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    before = len(os.listdir("/proc/self/fd"))
                    self.send_rights(b"BFPIDS1\n", [fd] * count)
                    with self.assertRaises(b.Refusal):
                        self.channel.bootstrap(os.getuid())
                    self.assertEqual(len(os.listdir("/proc/self/fd")), before)
                finally:
                    os.close(fd)

    def test_wrong_mode_owner_type_marker_missing_rights_and_early_eof(self):
        for fault in ("mode", "owner", "type", "marker", "missing", "eof"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                parent, child = socket.socketpair()
                peer = s.peer_socket(child)
                channel = s.Channel(child, b.Budget(time.monotonic_ns() + 180_000_000_000), peer[3])
                fd = os.open(directory if fault != "type" else "/dev/null", os.O_RDONLY)
                try:
                    if fault == "mode":
                        os.chmod(directory, 0o1700)
                    payload = b"INVALID!" if fault == "marker" else b"BFPIDS1\n"
                    if fault == "eof":
                        parent.shutdown(socket.SHUT_WR)
                    elif fault == "missing":
                        parent.sendall(payload)
                    else:
                        parent.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))])
                    before = len(os.listdir("/proc/self/fd"))
                    with self.assertRaises(b.Refusal):
                        channel.bootstrap(os.getuid() + 1 if fault == "owner" else os.getuid())
                    self.assertEqual(len(os.listdir("/proc/self/fd")), before)
                finally:
                    os.close(fd)
                    parent.close()
                    child.close()
                    os.close(peer[3])

    def test_late_rights_in_frame_and_terminal_eof_are_closed(self):
        for terminal in (False, True):
            fd = os.open("/dev/null", os.O_RDONLY)
            try:
                before = len(os.listdir("/proc/self/fd"))
                self.send_rights(b"x", [fd])
                with self.assertRaises(b.Refusal):
                    self.channel.eof() if terminal else self.channel.request()
                self.assertEqual(len(os.listdir("/proc/self/fd")), before)
            finally:
                os.close(fd)

    def test_literal_frame_encoding_sequence_duplicate_and_size_refusals(self):
        for payload in (b"\0\0\0\0", struct.pack("!I", 16385),
                        frame({"version": 1, "sequence": 2, "op": "LocateBatch"}),
                        frame({"version": True, "sequence": 1, "op": "LocateBatch"}),
                        struct.pack("!I", 31) + b'{"version":1,"version":1,"x":0}',
                        struct.pack("!I", 1) + b"\xff"):
            with self.subTest(payload=payload[:30]):
                # Independent socket endpoints prevent failed frame residue
                # from affecting a subsequent rejection control.
                p, c = socket.socketpair()
                peer = s.peer_socket(c)
                channel = s.Channel(c, b.Budget(time.monotonic_ns() + 180_000_000_000), peer[3])
                try:
                    p.sendall(payload)
                    p.shutdown(socket.SHUT_WR)
                    with self.assertRaises((b.Refusal, ValueError, UnicodeError)):
                        channel.request()
                finally:
                    p.close(); c.close(); os.close(peer[3])

    def test_terminal_requires_actual_eof_and_original_deadline_is_not_renewed(self):
        self.parent.sendall(b"extra")
        self.parent.shutdown(socket.SHUT_WR)
        with self.assertRaises(b.Refusal):
            self.channel.eof()
        now = [1]
        budget = l.RuntimeBudget(180_000_000_001, lambda: now[0])
        original = budget.deadline_ns
        now[0] = budget.work_ns - 1
        budget.begin_cleanup()
        now[0] = budget.work_ns + 1
        budget.read(1)
        self.assertEqual(budget.deadline_ns, original)
        now[0] = original
        with self.assertRaises(b.Refusal):
            budget.read(1)

    def test_pipe_stdin_never_becomes_socketpair_authority(self):
        read, write = os.pipe()
        try:
            with patch.object(s.os, "fstat", return_value=os.fstat(read)):
                with patch.object(s.os, "write") as output:
                    self.assertEqual(s.main(["supervise", "1"]), 1)
                    self.assertEqual(output.call_args.args[1], b"native-pids-supervisor: refused\n")
        finally:
            os.close(read); os.close(write)

    def test_reverse_api_reservation_waits_for_matching_same_sequence_debit_ack(self):
        self.channel.sequence = 7
        debit = []
        errors = []
        def parent():
            try:
                header = self.parent.recv(4)
                size = struct.unpack("!I", header)[0]
                body = bytearray()
                while len(body) < size:
                    body.extend(self.parent.recv(size - len(body)))
                value = json.loads(body)
                self.assertEqual(value, {"version": 1, "sequence": 7, "op": "ReserveApi",
                                         "reservation": 1, "units": 1, "max_body_bytes": 32768})
                debit.append((1, 32768))
                self.parent.sendall(frame({"version": 1, "sequence": 7,
                                           "op": "ApiReservationAccepted", "reservation": 1}))
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=parent)
        thread.start()
        try:
            self.channel.reserve_api(1, 32768)
        finally:
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(debit, [(1, 32768)])
        self.assertEqual((self.channel.sequence, self.channel.reservation, self.budget.frames), (7, 1, 1))

    def test_reverse_api_stale_reservation_ack_refuses_and_keeps_charge(self):
        self.channel.sequence = 3
        self.parent.sendall(frame({"version": 1, "sequence": 3, "op": "ApiReservationAccepted", "reservation": 2}))
        with self.assertRaises(b.Refusal):
            self.channel.reserve_api(1, 4096)
        self.assertEqual(self.channel.reservation, 1)
        self.assertGreater(self.budget.output, 0)


class WatchdogTests(unittest.TestCase):
    def spawn(self, resistant=False):
        read, write = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read)
            os.setpgid(0, 0)
            if resistant:
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
            os.write(write, b"R")
            os.close(write)
            while True:
                signal.pause()
        os.close(write)
        self.assertEqual(os.read(read, 1), b"R")
        os.close(read)
        return pid, os.pidfd_open(pid)

    def test_parent_death_kills_term_resistant_child_and_reaps(self):
        peer, peerfd = self.spawn()
        child, childfd = self.spawn(resistant=True)
        try:
            os.kill(peer, signal.SIGKILL)
            os.waitpid(peer, 0)
            begin = time.monotonic()
            self.assertEqual(s.monitor(peerfd, child, childfd, time.monotonic_ns() + 5_000_000_000), 1)
            self.assertLess(time.monotonic() - begin, 2)
            with self.assertRaises(ChildProcessError):
                os.waitpid(child, os.WNOHANG)
        finally:
            for pid, fd in ((peer, peerfd), (child, childfd)):
                try:
                    os.killpg(pid, signal.SIGKILL)
                    os.waitpid(pid, 0)
                except (ChildProcessError, ProcessLookupError):
                    pass
                os.close(fd)

    def test_external_cancellation_has_bounded_kill_and_reap(self):
        child, childfd = self.spawn(resistant=True)
        peerfd = os.pidfd_open(os.getpid())
        timer = threading.Timer(0.05, lambda: os.kill(os.getpid(), signal.SIGTERM))
        try:
            timer.start()
            self.assertEqual(s.monitor(peerfd, child, childfd, time.monotonic_ns() + 5_000_000_000), 1)
            with self.assertRaises(ChildProcessError):
                os.waitpid(child, os.WNOHANG)
        finally:
            timer.cancel(); timer.join()
            try:
                os.killpg(child, signal.SIGKILL)
                os.waitpid(child, 0)
            except (ChildProcessError, ProcessLookupError):
                pass
            os.close(peerfd); os.close(childfd)


class RootSessionTests(unittest.TestCase):
    def test_isolated_startup_resolves_only_fixed_siblings_and_keeps_diagnostic_closed(self):
        result = subprocess.run([sys.executable, "-I", str(Path(s.__file__).resolve()), "supervise", "1"],
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=2, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"DOCKERLENS_NATIVE_PIDS_START: s=s_fd0 k=guard\nnative-pids-supervisor: refused\n")

    def test_fixed_sibling_loader_rejects_wrong_cached_module_paths(self):
        script = str(Path(s.__file__).resolve())
        code = ("import sys,types,runpy,pathlib\n"
                "for name in ('native_pids_locator','native_pids_boundary'):\n"
                " m=types.ModuleType(name);m.__file__='/untrusted/'+name+'.py';sys.modules[name]=m\n"
                f"scope=runpy.run_path({script!r})\n"
                f"expected=pathlib.Path({script!r}).parent\n"
                "assert pathlib.Path(scope['locator'].__file__).resolve()==expected/'native_pids_locator.py'\n"
                "assert pathlib.Path(scope['boundary'].__file__).resolve()==expected/'native_pids_boundary.py'\n")
        result = subprocess.run([sys.executable, "-I", "-c", code],
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=2, check=False)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"", b""))

    def test_full_six_role_session_over_actual_descriptor_bootstrap_and_framed_ipc(self):
        from test_native_pids_locator import LocatorTests
        harness = LocatorTests()
        def run(tree):
            runtime = harness.runtime(tree)
            parent, child_stream = socket.socketpair()
            capture = os.open(tree.root, os.O_RDONLY | os.O_DIRECTORY)
            child = os.fork()
            if child == 0:
                parent.close()
                peer = s.peer_socket(child_stream)
                received = None
                try:
                    channel = s.Channel(child_stream, tree.source.budget, peer[3])
                    received = channel.bootstrap(os.getuid())
                    tree.source.adopt_capture_directory(received)
                    received = None
                    runtime.retained.add(tree.source.capture_directory)
                    original_response = channel.response
                    def checked_response(value):
                        if value.get("op") == "SealMeasurements":
                            os.fstat(tree.source.capture_directory)
                        if value.get("op") == "OuterFinalize":
                            try:
                                os.fstat(tree.source.capture_directory)
                            except OSError:
                                pass
                            else:
                                raise AssertionError("capture capability survived finalization")
                        original_response(value)
                    channel.response = checked_response
                    s.serve_session(channel, s.RootSession(runtime, tree.ids))
                    result = 0
                except BaseException:
                    result = 1
                finally:
                    if received is not None:
                        os.close(received)
                    child_stream.close()
                    os.close(peer[3])
                os._exit(result)
            child_stream.close()
            peer = s.peer_socket(parent)
            channel = s.Channel(parent, l.RuntimeBudget(time.monotonic_ns() + 50_000_000_000), peer[3])
            sequence = 0
            reaped = False
            try:
                parent.sendmsg([b"BFPIDS1\n"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [capture]))])
                self.assertEqual(channel.exact(8), b"BFREADY\n")
                def call(operation, **fields):
                    nonlocal sequence
                    sequence += 1
                    channel.send_raw(frame({"version": 1, "sequence": sequence, "op": operation, **fields}))
                    if operation == "OuterFinalize":
                        parent.shutdown(socket.SHUT_WR)
                    return channel.request()
                self.assertEqual(call("LocateBatch")["status"], "ok")
                for slot in l.ORDER:
                    for phase in (("before", "at_limit", "after_failure", "after_release") if slot.endswith("16") else
                                  ("before", "at_limit", "control", "after_release")):
                        self.assertEqual(call("Sample", slot=slot, phase=phase)["sample"]["current"], 1)
                call("RecheckBatch")
                self.assertEqual(call("SealMeasurements")["status"], "sealed")
                self.assertEqual(call("OuterFinalize")["status"], "finalized")
                self.assertEqual(channel.receive(1)[0], b"")
                self.assertEqual(os.waitpid(child, 0)[1], 0)
                reaped = True
            finally:
                parent.close(); os.close(peer[3]); os.close(capture)
                if not reaped:
                    try:
                        os.kill(child, signal.SIGKILL)
                        os.waitpid(child, 0)
                    except (ProcessLookupError, ChildProcessError):
                        pass
        harness.run_tree(True, run)

    def test_six_slot_seal_retains_original_outer_during_intentional_inner_removal(self):
        from test_native_pids_locator import LocatorTests
        harness = LocatorTests()
        def run(tree):
            capture = os.open(tree.root, os.O_RDONLY | os.O_DIRECTORY)
            tree.source.adopt_capture_directory(capture)
            runtime = harness.runtime(tree)
            session = s.RootSession(runtime, tree.ids)
            channel = type("Terminal", (), {"eof": lambda _self: None})()
            sequence = 0
            def handle(operation, **fields):
                nonlocal sequence
                sequence += 1
                return session.handle({"version": 1, "sequence": sequence, "op": operation, **fields}, channel)
            handle("LocateBatch")
            for slot in l.ORDER:
                for phase in (("before", "at_limit", "after_failure", "after_release") if slot.endswith("16") else
                              ("before", "at_limit", "control", "after_release")):
                    sample = handle("Sample", slot=slot, phase=phase)["sample"]
                    self.assertEqual(sample["current"], 1)
            original_daemon = runtime.daemon
            self.assertEqual(handle("SealMeasurements")["status"], "sealed")
            self.assertTrue(tree.source.budget.cleanup_only)
            self.assertEqual(runtime.bound, {})
            self.assertIs(runtime.daemon, original_daemon)
            os.fstat(capture)  # source must retain it through intentional cleanup
            for pid in range(200, 206):
                (tree.proc / str(pid) / "stat").write_bytes(b"intentionally removed")
            self.assertEqual(handle("OuterFinalize")["status"], "finalized")
            self.assertEqual(tree.source.owned, set())
            with self.assertRaises(OSError):
                os.fstat(capture)
        harness.run_tree(True, run)

    def test_capture_close_failure_prevents_finalized_ack_and_closes_other_source_fds(self):
        from test_native_pids_locator import LocatorTests
        harness = LocatorTests()
        def run(tree):
            capture = os.open(tree.root, os.O_RDONLY | os.O_DIRECTORY)
            tree.source.adopt_capture_directory(capture)
            runtime = harness.runtime(tree)
            session = s.RootSession(runtime, tree.ids)
            session.phase = "sealed"
            tree.source.budget.begin_cleanup()
            channel = type("Terminal", (), {"eof": lambda _self: None})()
            original_close = tree.source.close_fd
            closed = []
            def close(fd):
                original_close(fd)
                closed.append(fd)
                if fd == capture:
                    raise OSError("private cleanup failure")
            with patch.object(tree.source, "close_fd", side_effect=close):
                with self.assertRaises(b.Refusal):
                    session.handle({"version": 1, "sequence": 1, "op": "OuterFinalize"}, channel)
            self.assertTrue(session.failed)
            self.assertEqual(tree.source.owned, set())
            self.assertEqual(closed.count(capture), 1)
        harness.run_tree(True, run)

    def test_unknown_slot_order_seal_before_complete_and_cleanup_failure_never_ack(self):
        from test_native_pids_locator import LocatorTests
        for fault in ("slot", "order", "seal", "cleanup"):
            harness = LocatorTests()
            def run(tree):
                runtime = harness.runtime(tree)
                session = s.RootSession(runtime, tree.ids)
                channel = type("Terminal", (), {"eof": lambda _self: None})()
                session.handle({"version": 1, "sequence": 1, "op": "LocateBatch"}, channel)
                if fault in ("slot", "order"):
                    request = {"version": 1, "sequence": 2, "op": "Sample", "slot": "arbitrary" if fault == "slot" else "cli16",
                               "phase": "before" if fault == "slot" else "control"}
                elif fault == "seal":
                    request = {"version": 1, "sequence": 2, "op": "SealMeasurements"}
                else:
                    session.phase = "sealed"
                    tree.source.budget.begin_cleanup()
                    request = {"version": 1, "sequence": 2, "op": "OuterFinalize"}
                    with patch.object(tree.source, "close", side_effect=OSError("private")):
                        with self.assertRaises(OSError):
                            session.handle(request, channel)
                    self.assertTrue(session.failed)
                    return
                with self.assertRaises(b.Refusal):
                    session.handle(request, channel)
                self.assertTrue(session.failed)
            with self.subTest(fault=fault):
                harness.run_tree(True, run)


class RootFactoryTests(unittest.TestCase):
    """Fixed factory executes source I/O; namespace/pidfd kernel facts simulated."""

    def test_closed_lane_expectations_match_canonical_profile_and_acquisition_ceiling(self):
        root = Path(__file__).resolve().parents[1]
        profiles = json.loads((root / "docs/evidence/command-clear-independent-review-40119803977.json").read_text())["exact_profiles"]
        script = (root / "scripts/native-conformance.sh").read_text()
        ceiling = (root / "src/acquisition.rs").read_text()
        self.assertIn("const MAX_KNOWN_API_MINOR: u16 = 49;", ceiling)
        self.assertEqual(set(s.LANES), {"debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"})
        for lane, (uid, executable, engine, api) in s.LANES.items():
            self.assertIn(lane + ") image=", script)
            self.assertEqual(uid, 1000 if lane.endswith("rootless") else 0)
            if lane.startswith("debian11"):
                self.assertEqual((executable, engine, api), (("usr", "sbin", "dockerd"), profiles["debian_engine"],
                    profiles["debian_acquisition_rendering_and_advertised_api"]))
                self.assertIn("DEBIAN_DOCKER_PACKAGE='" + profiles["debian_package"] + "'", script)
            else:
                self.assertEqual((executable, engine, api), (("usr", "local", "bin", "dockerd"),
                                                           profiles["upstream_engine"], profiles["upstream_acquisition_api"]))
                self.assertIn(":v" + engine + "@sha256:", script)

    def run_factory(self, operation, *, rootful=False):
        from test_native_pids_locator import LocatorTests
        harness = LocatorTests()
        def run(tree):
            (tree.ns / "outer").touch()
            tree.parents[str(tree.ns / "outer")] = "reader"
            tree.parents[str(tree.ns / "daemon")] = "outer"
            (tree.proc / "100/ns/pid").unlink()
            (tree.proc / "100/ns/pid").symlink_to(tree.ns / "outer")
            (tree.ns / "outer-cgroup").touch()
            (tree.proc / "100/ns/cgroup").unlink()
            (tree.proc / "100/ns/cgroup").symlink_to(tree.ns / "outer-cgroup")
            (tree.proc / "100/status").write_text("Pid: 100\nTgid: 100\nUid: 0 0 0 0\nNSpid: 100 1\nNStgid: 100 1\n")
            (tree.proc / "110/status").write_text("Pid: 110\nTgid: 110\nUid: 1000 1000 1000 1000\nNSpid: 110 2 1\nNStgid: 110 2 1\n")
            for index, slot in enumerate(l.ORDER):
                pid = 200 + index
                vector = f"{pid} {70 + index} 1" if rootful else f"{pid} {500 + index} {70 + index} 1"
                if rootful:
                    tree.parents[str(tree.ns / slot)] = "outer"
                (tree.proc / str(pid) / "status").write_text(
                    f"Pid: {pid}\nTgid: {pid}\nUid: 1000 1000 1000 1000\nNSpid: {vector}\nNStgid: {vector}\n")
            executable = tree.rootfs / "usr/local/bin/dockerd"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"immutable upstream fixture executable")
            peer_pid, peer_uid = (100, 0) if rootful else (110, 1000)
            (tree.proc / str(peer_pid) / "exe").unlink()
            (tree.proc / str(peer_pid) / "exe").symlink_to(executable)
            (tree.rootfs / "sys/fs").mkdir(parents=True)
            device = os.stat(tree.cg).st_dev
            (tree.proc / "100/mountinfo").write_text(
                f"10 0 {os.major(device)}:{os.minor(device)} /owned /sys/fs/cgroup rw - cgroup2 cgroup rw\n")
            original_open = tree.source.open
            def guest_mount_open(name, parent=None, **options):
                if (name == "cgroup" and parent is not None
                        and os.readlink("/proc/self/fd/" + str(parent)) == str(tree.rootfs / "sys/fs")):
                    # Simulate only the guest mount dentry: returned capability
                    # is the actual configured-root directory, not a JSON tuple.
                    return original_open(str(tree.cg / "owned"), directory=True)
                return original_open(name, parent, **options)
            tree.source.open = guest_mount_open
            (tree.root / "socket").mkdir()
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(str(tree.root / "socket/docker.sock"))
            listener.listen(1)
            capture = os.open(tree.root, os.O_RDONLY | os.O_DIRECTORY)
            tree.source.adopt_capture_directory(capture)
            session = s.RuntimeBoundSession(tree.source)
            calls = []
            channel = type("Owner", (), {"reserve_api": lambda _self, units, maximum: calls.append((units, maximum)),
                                         "eof": lambda _self: None})()
            request = {"version": 1, "sequence": 1, "op": "RootBindRuntime", "outer_pid": 100, "outer_start": 1000,
                       "context": {"backend": "podman", "candidate": "a" * 40, "run": "run1",
                                   "lane": "upstream-rootful" if rootful else "upstream-rootless", "outer_id": "b" * 64},
                       "owner_labels": {"io.dockerlens.native-pids": "run1"},
                       "external_source": {"bytes": 1024 * 1024, "reads": 1024}}
            class Connected:
                def getsockopt(_self, _level, option, *_size):
                    return os.dup(tree.pipe[0]) if option == 77 else struct.pack("3i", peer_pid, peer_uid, peer_uid)
            def actual_response(address, method, route, **options):
                self.assertEqual(method, "GET")
                lease = options["peer_lease"](Connected())
                try:
                    lease.check()
                    if route == "/version":
                        self.assertEqual(options["max_response_bytes"], 4096)
                        body = {"Version": "29.8.1", "ApiVersion": "1.56", "MinAPIVersion": "1.44"}
                    else:
                        cid = route.split("/")[-2]
                        slot = next(slot for slot, value in tree.ids.items() if value == cid)
                        index = l.ORDER.index(slot)
                        body = {"Id": cid, "RestartCount": 0,
                                "Config": {"Labels": {"io.dockerlens.native-pids": "run1",
                                                      "io.dockerlens.native-pids-slot": slot}},
                                "State": {"Status": "running", "Running": True, "Restarting": False,
                                          "Paused": False, "Dead": False, "Pid": 70 + index,
                                          "StartedAt": "2026-10-25T12:00:00Z"}}
                    lease.check()
                    return 200, json.dumps(body).encode()
                finally:
                    lease.close()
            try:
                with patch.object(l.http, "request", side_effect=actual_response):
                    return operation(tree, session, channel, request, calls)
            finally:
                listener.close()
        return harness.run_tree(True, run)

    def test_fixed_factory_pending_confirm_then_later_six_ids_and_source_measurements(self):
        def run(tree, session, channel, request, calls):
            self.assertEqual(session.handle(request, channel)["status"], "pending")
            self.assertEqual(calls, [(1, 4096)])
            original = session.runtime.outer
            self.assertEqual(session.handle({"version": 1, "sequence": 2, "op": "ConfirmRuntime"}, channel)["status"], "confirmed")
            self.assertIs(session.runtime.outer, original)
            self.assertEqual(session.handle({"version": 1, "sequence": 3, "op": "LocateBatch", "slots": tree.ids}, channel)["status"], "ok")
            self.assertEqual(calls, [(1, 4096)] + [(1, 32768)] * 12)
            response = session.handle({"version": 1, "sequence": 4, "op": "Sample", "slot": "cli16", "phase": "before"}, channel)
            self.assertEqual(response["sample"]["current"], 1)
            self.assertEqual(response["sample"]["task_namespace_ids"], [[200, [200, 500, 70, 1], [200, 500, 70, 1]]])
        self.run_factory(run)

    def test_rootful_direct_daemon_may_be_outer_init_in_same_pid_namespace_and_group(self):
        def run(tree, session, channel, request, _calls):
            self.assertEqual(session.handle(request, channel)["status"], "pending")
            runtime = session.runtime
            self.assertEqual(runtime.daemon.pid, runtime.outer.pid)
            self.assertEqual(b.identity(runtime.daemon.namespaces[0]), b.identity(runtime.outer.namespaces[0]))
            self.assertEqual(runtime.daemon.membership, runtime.outer.membership)
            session.handle({"version": 1, "sequence": 2, "op": "ConfirmRuntime"}, channel)
            self.assertEqual(session.handle({"version": 1, "sequence": 3, "op": "LocateBatch", "slots": tree.ids}, channel)["status"], "ok")
        self.run_factory(run, rootful=True)

    def test_configured_outer512_is_exact_guest_mount_ancestor_when_pid1_moved_to_init_scope(self):
        def run(tree, session, channel, request, _calls):
            tree.make_group(tree.cg / "owned/init.scope", "max", [100])
            (tree.cg / "owned/cgroup.procs").write_text("110\n")
            (tree.cg / "owned/cgroup.threads").write_text("110\n")
            (tree.proc / "100/cgroup").write_text("0::/owned/init.scope\n")
            self.assertEqual(session.handle(request, channel)["status"], "pending")
            self.assertEqual(session.runtime.outer.membership, ("owned", "init.scope"))
            self.assertEqual(session.runtime.outer_group.membership, ("owned",))
            self.assertEqual(tree.source.values(session.runtime.outer_group)[0], 512)
            session.handle({"version": 1, "sequence": 2, "op": "ConfirmRuntime"}, channel)
            self.assertEqual(session.handle({"version": 1, "sequence": 3, "op": "LocateBatch", "slots": tree.ids}, channel)["status"], "ok")
        self.run_factory(run)

    def test_no_nearest512_fallback_and_changed_guest_mount_record_refuse(self):
        for fault in ("wrong_root_limit", "mount_record"):
            def run(tree, session, channel, request, calls):
                if fault == "wrong_root_limit":
                    tree.make_group(tree.cg / "owned/init.scope", 512, [100])
                    (tree.cg / "owned/cgroup.procs").write_text("110\n")
                    (tree.proc / "100/cgroup").write_text("0::/owned/init.scope\n")
                    (tree.cg / "owned/pids.max").write_text("64\n")
                    with self.assertRaises(b.Refusal):
                        session.handle(request, channel)
                    self.assertEqual(calls, [])
                else:
                    session.handle(request, channel)
                    path = tree.proc / "100/mountinfo"
                    path.write_text(path.read_text().replace(" cgroup rw\n", " cgroup ro\n"))
                    with self.assertRaises(b.Refusal):
                        session.handle({"version": 1, "sequence": 2, "op": "ConfirmRuntime"}, channel)
                self.assertTrue(session.failed)
            with self.subTest(fault=fault):
                self.run_factory(run)

    def test_full_factory_transcript_actual_ipc_has_30_owner_requests_and_25_debit_acks(self):
        include_recheck = getattr(self, "inspect_recheck", True)
        expected_frames = 55 if include_recheck else 48
        expected_requests = 30 if include_recheck else 29
        expected_reservations = 25 if include_recheck else 19
        expected_body = 790528 if include_recheck else 593920
        expected_inspects = 24 if include_recheck else 18
        expected_inspect_bytes = 786432 if include_recheck else 589824
        def run(tree, session, _channel, request, _calls):
            parent, child_stream = socket.socketpair()
            child = os.fork()
            if child == 0:
                parent.close()
                peer = s.peer_socket(child_stream)
                try:
                    channel = s.Channel(child_stream, tree.source.budget, peer[3])
                    original_response = channel.response
                    def checked_response(value):
                        if value.get("op") == "OuterFinalize":
                            assert channel.budget.frames == expected_frames
                            assert tree.source.owned == set()
                        original_response(value)
                    channel.response = checked_response
                    s.serve_session(channel, session)
                    result = 0
                except BaseException:
                    result = 1
                finally:
                    child_stream.close()
                    os.close(peer[3])
                os._exit(result)
            child_stream.close()
            peer = s.peer_socket(parent)
            channel = s.Channel(parent, l.RuntimeBudget(time.monotonic_ns() + 50_000_000_000), peer[3])
            sequence, reservations, body_bytes = 0, 0, 0
            reaped = False
            try:
                def call(operation, **fields):
                    nonlocal sequence, reservations, body_bytes
                    sequence += 1
                    channel.send_raw(frame({"version": 1, "sequence": sequence, "op": operation, **fields}))
                    if operation == "OuterFinalize":
                        parent.shutdown(socket.SHUT_WR)
                    while True:
                        value = channel.object()
                        self.assertEqual(value["sequence"], sequence)
                        if value["op"] != "ReserveApi":
                            return value
                        reservations += 1
                        self.assertEqual(value["reservation"], reservations)
                        self.assertEqual(value["units"], 1)
                        body_bytes += value["max_body_bytes"]
                        # Independent parent ledger precedes the source's call.
                        self.assertLessEqual(body_bytes, 2 * 1024 * 1024)
                        channel.send_raw(frame({"version": 1, "sequence": sequence,
                                               "op": "ApiReservationAccepted", "reservation": reservations}))
                fields = {key: value for key, value in request.items() if key not in ("version", "sequence", "op")}
                self.assertEqual(call("RootBindRuntime", **fields)["status"], "pending")
                self.assertEqual(call("ConfirmRuntime")["status"], "confirmed")
                call("LocateBatch", slots=tree.ids)
                counts = {slot: 1 for slot in l.ORDER}
                failures = 0
                for slot_index, slot in enumerate(l.ORDER):
                    for phase in (("before", "at_limit", "after_failure", "after_release") if slot.endswith("16") else
                                  ("before", "at_limit", "control", "after_release")):
                        count = 1 if phase in ("before", "after_release") else (16 if slot.endswith("16") else 33)
                        members = [200 + slot_index]
                        for index in range(1, count):
                            pid = 1000 + slot_index * 100 + index
                            if not (tree.proc / str(pid)).exists():
                                tree.make_process(pid, slot, (pid, 5000 + pid, 7000 + pid, index + 1), "owned/" + slot, 1000)
                            members.append(pid)
                        counts[slot] = count
                        directory = tree.cg / "owned" / slot
                        for name in ("cgroup.threads", "cgroup.procs"):
                            (directory / name).write_text("".join(str(pid) + "\n" for pid in members))
                        (directory / "pids.current").write_text(str(count) + "\n")
                        (tree.cg / "owned/pids.current").write_text(str(2 + sum(counts.values())) + "\n")
                        (tree.proc / "loadavg").write_text(f"0.00 0.00 0.00 1/{1000 + sum(counts.values()) - 6} 200\n")
                        if phase == "after_failure":
                            failures += 1
                            (directory / "pids.events").write_text("max 1\n")
                            (directory / "pids.events.local").write_text("max 1\n")
                            (tree.cg / "owned/pids.events").write_text(f"max {failures}\n")
                        sample = call("Sample", slot=slot, phase=phase)["sample"]
                        self.assertEqual(sample["current"], count)
                        self.assertEqual(len(sample["tasks"]), count)
                        self.assertTrue(sample["attribution"]["complete_chain"])
                if include_recheck:
                    call("RecheckBatch")
                self.assertEqual(call("SealMeasurements")["status"], "sealed")
                final = call("OuterFinalize")
                self.assertEqual(final["status"], "finalized")
                self.assertEqual((sequence, reservations, body_bytes),
                                 (expected_requests, expected_reservations, expected_body))
                self.assertEqual(final["reservations"], {"inspect_calls_reserved": expected_inspects,
                    "inspect_body_bytes_reserved": expected_inspect_bytes, "runtime_probe_calls_reserved": 1,
                    "runtime_probe_body_bytes_reserved": 4096})
                ledger = final["source_ledger"]
                self.assertEqual(ledger["external_reserved"], {"bytes": 1048576, "reads": 1024})
                self.assertEqual(ledger["root_reserved"]["bytes"] + 1048576, ledger["total_reserved"]["bytes"])
                self.assertLessEqual(ledger["total_reserved"]["bytes"], 33554432)
                self.assertLessEqual(ledger["total_reserved"]["reads"], 65536)
                self.assertEqual(ledger["fds"]["source_owned_remaining"], 0)
                final_frame = len(json.dumps(final, separators=(",", ":"), sort_keys=True).encode()) + 4
                self.assertLessEqual(ledger["output_reserved_before_final"] + final_frame, 65536)
                self.assertEqual(channel.receive(1)[0], b"")
                self.assertEqual(os.waitpid(child, 0)[1], 0)
                reaped = True
            finally:
                parent.close(); os.close(peer[3])
                if not reaped:
                    try:
                        os.kill(child, signal.SIGKILL)
                        os.waitpid(child, 0)
                    except (ProcessLookupError, ChildProcessError):
                        pass
        self.run_factory(run)

    def test_canonical_18_inspect_flow_has_48_input_frames_and_19_api_debits(self):
        self.inspect_recheck = False
        self.test_full_factory_transcript_actual_ipc_has_30_owner_requests_and_25_debit_acks()

    def test_unconfirmed_work_and_changed_original_outer_never_confirm(self):
        for fault in ("unconfirmed", "replacement", "labels", "start"):
            def run(tree, session, channel, request, calls):
                if fault == "labels":
                    request["owner_labels"] = {"arbitrary.selector": "run1"}
                if fault == "start":
                    request["outer_start"] = 999
                if fault in ("labels", "start"):
                    with self.assertRaises((b.Refusal, OSError)):
                        session.handle(request, channel)
                    self.assertEqual(calls, [])
                    return
                session.handle(request, channel)
                if fault == "replacement":
                    (tree.proc / "100/stat").write_bytes(b"100 (reused) S " + b"0 " * 18 + b"9999\n")
                operation = {"version": 1, "sequence": 2, "op": "ConfirmRuntime"} if fault == "replacement" else {
                    "version": 1, "sequence": 2, "op": "LocateBatch", "slots": tree.ids}
                with self.assertRaises(b.Refusal):
                    session.handle(operation, channel)
                self.assertTrue(session.failed)
            with self.subTest(fault=fault):
                self.run_factory(run)


class HeldAncestryFixture:
    """Independent inert kernel model for the guard, not a source authority."""

    PEER, SUDO, SUPERVISOR = 41, 42, 43
    UID, FOREIGN = 37, 61
    PROC, CGROUP, TIME, SUDO_FILE = 900, 901, 902, 903

    def __init__(self, ancestor_uid=None, peer_uid=UID, links=None):
        self.peer_uid = peer_uid
        self.log = []
        self.proc, self.reader_cgroup_namespace = self.PROC, self.CGROUP
        self.reader_time_namespace = self.TIME
        self.ppids = dict(links or {self.SUPERVISOR: self.SUDO, self.SUDO: self.PEER})
        self.held, self.current, self.times, self.live = {}, {}, {}, {}
        self.identities = {self.CGROUP: (1, 1), self.TIME: (2, 2), self.SUDO_FILE: (3, 3)}
        self.after_exe = None
        self.fixed_sudo_error = None
        for pid in {self.PEER, *self.ppids}:
            vector = (peer_uid,) * 4 if pid == self.PEER else (0,) * 4
            if pid == self.SUDO and ancestor_uid is not None:
                vector = ancestor_uid
            process = b.Process(pid, pid + 100, pid + 1000, pid + 2000, pid + 3000,
                (pid + 4000, pid + 5000, self.CGROUP), (),
                ((4, pid), ((5, pid), 6), ((7, pid), (8, pid), (1, 1))),
                ((pid,), vector, (pid,)))
            self.held[pid] = process
            self.current[pid] = process
            self.times[pid], self.live[pid] = self.TIME, True
            self.identities[pid + 6000] = (3, 3)  # fixed sudo executable witness

    def process(self, pid, start):
        self.log.append(("process", pid, start))
        b.require(pid in self.held and self.held[pid].start == start)
        self.check_process(self.held[pid])
        return self.held[pid]

    def check_process(self, process):
        self.log.append(("check", process.pid))
        b.require(self.live[process.pid] and self.current[process.pid] == process
                  and self.times[process.pid] == self.reader_time_namespace)

    def read(self, parent, name, maximum):
        self.log.append(("read", parent, name, maximum))
        if parent == self.PROC and name.endswith("/stat"):
            pid = int(name.split("/")[0])
            b.require(pid in self.current and maximum == 1024)
            return (f"{pid} (fixture) S ".encode() + b"0 " * 18
                    + str(self.current[pid].start).encode() + b"\n")
        if name == "status":
            pid = parent - 1000
            b.require(pid in self.ppids and maximum == 4096)
            return b"PPid:\t" + str(self.ppids[pid]).encode() + b"\n"
        raise AssertionError("unexpected fixture read")

    def open(self, name, parent=None, directory=False, magic=False):
        self.log.append(("open", name, parent, directory, magic))
        if name == "self/ns/time":
            b.require(parent == self.PROC and magic)
            return self.TIME
        if name == "ns/time":
            b.require(parent == self.held[self.PEER].directory and magic)
            return self.times[self.PEER]
        if name == "/usr/bin/sudo":
            b.require(parent is None and not magic)
            if self.fixed_sudo_error:
                raise self.fixed_sudo_error
            return self.SUDO_FILE
        if name == "exe":
            pid = parent - 1000
            b.require(pid != self.SUPERVISOR and pid != self.PEER and magic)
            if self.after_exe is not None:
                callback, self.after_exe = self.after_exe, None
                callback(self)
            return pid + 6000
        raise AssertionError("unexpected fixture open")


class SudoAncestorUidTests(unittest.TestCase):
    """Full guard controls with authored process facts, never /proc or sudo."""

    def run_guard(self, fixture):
        recorder = s.StartupRecorder("w", True)
        with patch.object(s, "_STARTUP", recorder), patch.object(b, "STARTUP_OBSERVER", recorder), \
                patch.object(l, "live") as peer_live, patch.object(s.os, "getppid", return_value=fixture.SUPERVISOR), \
                patch.object(b, "identity", side_effect=lambda fd: fixture.identities[fd]), patch.object(s.os, "write"):
            try:
                result = s.guard_parent(fixture,
                    (fixture.PEER, fixture.peer_uid, 0, 7000), fixture.SUPERVISOR)
            except (b.Refusal, OSError) as error:
                return None, error, recorder.value, peer_live.call_count
        return result, None, recorder.value, peer_live.call_count

    def test_independent_complete_uid_product_allows_only_legacy_and_exact_sudo_shape(self):
        import itertools
        p, foreign = HeldAncestryFixture.UID, HeldAncestryFixture.FOREIGN
        allowed = {(0, 0, 0, 0), (p, p, p, p), (p, 0, 0, 0)}
        for vector in itertools.product((0, p, foreign), repeat=4):
            with self.subTest(vector=vector):
                fixture = HeldAncestryFixture(vector)
                result, error, observed, _ = self.run_guard(fixture)
                if vector in allowed:
                    self.assertIs(result, fixture.held[fixture.PEER])
                    self.assertIsNone(error)
                    self.assertIsNone(observed)
                else:
                    self.assertIsNone(result)
                    self.assertIsInstance(error, b.Refusal)
                    self.assertEqual(observed, ("w", "anc_uid", "guard"))
                    self.assertFalse(any(event[:2] == ("read", fixture.held[fixture.SUDO].directory)
                                         for event in fixture.log))
                    self.assertNotIn(("open", "/usr/bin/sudo", None, False, False), fixture.log)

    def test_candidate_is_rejected_for_peer_and_supervisor_without_executable_lookup(self):
        from dataclasses import replace
        p = HeldAncestryFixture.UID
        for role, site in ((HeldAncestryFixture.PEER, "parent_uid"), (HeldAncestryFixture.SUPERVISOR, "anc_uid")):
            fixture = HeldAncestryFixture((p, 0, 0, 0))
            changed = replace(fixture.held[role], status=((role,), (p, 0, 0, 0), (role,)))
            fixture.held[role] = fixture.current[role] = changed
            result, error, observed, _ = self.run_guard(fixture)
            self.assertIsNone(result)
            self.assertIsInstance(error, b.Refusal)
            self.assertEqual(observed, ("w", site, "guard"))
            self.assertNotIn(("open", "/usr/bin/sudo", None, False, False), fixture.log)

    def test_supervisor_legacy_uniform_forms_keep_existing_guard_behavior(self):
        from dataclasses import replace
        p = HeldAncestryFixture.UID
        for vector in ((0,) * 4, (p,) * 4):
            fixture = HeldAncestryFixture()
            held = fixture.held[fixture.SUPERVISOR]
            changed = replace(held, status=((held.pid,), vector, (held.pid,)))
            fixture.held[fixture.SUPERVISOR] = fixture.current[fixture.SUPERVISOR] = changed
            result, error, _, _ = self.run_guard(fixture)
            self.assertIs(result, fixture.held[fixture.PEER])
            self.assertIsNone(error)
            self.assertNotIn(("open", "exe", held.directory, False, True), fixture.log)
        # This tests the existing ancestor predicate only. The original launch
        # also requires supervisor geteuid()==0; this creates no new role grant.

    def test_zero_peer_introduces_no_new_uid_shape(self):
        import itertools
        for vector in itertools.product((0, HeldAncestryFixture.FOREIGN), repeat=4):
            fixture = HeldAncestryFixture(vector, peer_uid=0)
            result, error, _, _ = self.run_guard(fixture)
            self.assertEqual(error is None, vector == (0, 0, 0, 0))
            if vector != (0, 0, 0, 0):
                self.assertIsNone(result)

    def test_new_route_has_identical_source_call_order_to_legacy_sudo_routes(self):
        p = HeldAncestryFixture.UID
        logs = []
        for vector in ((0, 0, 0, 0), (p, p, p, p), (p, 0, 0, 0)):
            fixture = HeldAncestryFixture(vector)
            result, error, observed, live_calls = self.run_guard(fixture)
            self.assertIs(result, fixture.held[fixture.PEER])
            self.assertIsNone(error)
            self.assertIsNone(observed)
            self.assertEqual(live_calls, 2)
            logs.append(fixture.log)
        self.assertEqual(logs[0], logs[1])
        self.assertEqual(logs[0], logs[2])
        self.assertEqual(logs[0].count(("open", "/usr/bin/sudo", None, False, False)), 1)
        self.assertEqual(logs[0].count(("open", "exe", 1042, False, True)), 1)
        self.assertNotIn(("open", "exe", 1043, False, True), logs[0])
        self.assertNotIn(("open", "exe", 1041, False, True), logs[0])
        self.assertEqual(sum(event[0] == "check" for event in logs[0]), 6)

    def test_no_saved_filesystem_foreign_or_arbitrary_mixed_identity_fallback(self):
        p, other = HeldAncestryFixture.UID, HeldAncestryFixture.FOREIGN
        for vector in ((other, 0, 0, 0), (p, p, 0, 0), (p, 0, p, 0), (p, 0, 0, p),
                       (p, 0, 0, other), (p, 0, other, 0), (0, p, 0, 0), (other, other, other, other),
                       (p, 0, 0, other + 1)):
            fixture = HeldAncestryFixture(vector)
            with patch.dict(os.environ, {"SUDO_UID": str(p), "SUDO_USER": "fixture-owner"}):
                result, error, observed, _ = self.run_guard(fixture)
            self.assertIsNone(result)
            self.assertIsInstance(error, b.Refusal)
            self.assertEqual(observed, ("w", "anc_uid", "guard"))

    def test_correct_uid_tuple_never_substitutes_for_fixed_sudo_executable(self):
        p = HeldAncestryFixture.UID
        for vector in ((0, 0, 0, 0), (p, p, p, p), (p, 0, 0, 0)):
            for different in ((3, 999), (999, 3)):
                fixture = HeldAncestryFixture(vector)
                fixture.identities[fixture.SUDO + 6000] = different
                result, error, observed, _ = self.run_guard(fixture)
                self.assertIsNone(result)
                self.assertIsInstance(error, b.Refusal)
                self.assertEqual(observed, ("w", "anc_exe", "guard"))
        fixture = HeldAncestryFixture((p, 0, 0, 0))
        failure = PermissionError(s.errno.EACCES, "fixed sudo unavailable")
        fixture.fixed_sudo_error = failure
        result, error, observed, _ = self.run_guard(fixture)
        self.assertIsNone(result)
        self.assertIs(error, failure)
        self.assertEqual(observed, ("w", "anc_sudo", "denied"))

    def test_new_shape_still_rejects_broken_ppid_or_non_sudo_intermediate(self):
        p = HeldAncestryFixture.UID
        for change in ("zero_ppid", "missing_link", "foreign_exe"):
            fixture = HeldAncestryFixture((p, 0, 0, 0))
            if change == "zero_ppid":
                fixture.ppids[fixture.SUDO] = 0
            elif change == "missing_link":
                fixture.ppids[fixture.SUDO] = 99
            else:
                fixture.identities[fixture.SUDO + 6000] = (999, 999)
            result, error, _, _ = self.run_guard(fixture)
            self.assertIsNone(result)
            self.assertIsInstance(error, b.Refusal)

    def test_held_credential_root_cgroup_namespace_start_and_liveness_drift_fail(self):
        from dataclasses import replace
        p = HeldAncestryFixture.UID
        for field in ("uid", "start", "root", "mount_identity", "membership", "namespaces", "time", "live", "ppid"):
            fixture = HeldAncestryFixture((p, 0, 0, 0))
            def drift(source, field=field):
                held = source.current[source.SUDO]
                if field == "uid":
                    source.current[source.SUDO] = replace(held, status=((held.pid,), (p,) * 4, (held.pid,)))
                elif field == "start":
                    source.current[source.SUDO] = replace(held, start=held.start + 1)
                elif field == "root":
                    source.current[source.SUDO] = replace(held, root=999)
                elif field == "mount_identity":
                    source.current[source.SUDO] = replace(held, identity=())
                elif field == "membership":
                    source.current[source.SUDO] = replace(held, membership=("moved",))
                elif field == "namespaces":
                    source.current[source.SUDO] = replace(held, namespaces=(999,) * 3)
                elif field == "time":
                    source.times[source.SUDO] = 999
                elif field == "live":
                    source.live[source.SUDO] = False
                else:
                    source.ppids[source.SUDO] = 99
            fixture.after_exe = drift
            result, error, observed, _ = self.run_guard(fixture)
            self.assertIsNone(result, field)
            self.assertIsInstance(error, b.Refusal, field)
            self.assertEqual(observed, ("w", "anc_recheck", "guard"), field)

    def test_peer_cgroup_time_parent_and_eight_link_bound_remain_required(self):
        from dataclasses import replace
        p = HeldAncestryFixture.UID
        fixture = HeldAncestryFixture((p, 0, 0, 0))
        parent = fixture.held[fixture.PEER]
        changed = replace(parent, namespaces=(parent.namespaces[0], parent.namespaces[1], 999))
        fixture.held[fixture.PEER] = fixture.current[fixture.PEER] = changed
        fixture.identities[999] = (99, 99)
        self.assertIsInstance(self.run_guard(fixture)[1], b.Refusal)
        fixture = HeldAncestryFixture((p, 0, 0, 0))
        fixture.times[fixture.PEER] = 999
        self.assertIsInstance(self.run_guard(fixture)[1], b.Refusal)
        fixture = HeldAncestryFixture((p, 0, 0, 0))
        recorder = s.StartupRecorder("w", True)
        with patch.object(s, "_STARTUP", recorder), patch.object(b, "STARTUP_OBSERVER", recorder), \
                patch.object(l, "live"), patch.object(s.os, "getppid", return_value=999), \
                patch.object(b, "identity", side_effect=lambda fd: fixture.identities[fd]), patch.object(s.os, "write"):
            with self.assertRaises(b.Refusal):
                s.guard_parent(fixture, (fixture.PEER, p, 0, 7000), fixture.SUPERVISOR)
        self.assertEqual(recorder.value, ("w", "parent_link", "guard"))
        links = {pid: pid + 1 for pid in range(43, 51)}
        links[51] = HeldAncestryFixture.PEER
        fixture = HeldAncestryFixture(links=links)
        result, error, observed, _ = self.run_guard(fixture)
        self.assertIsNone(result)
        self.assertIsInstance(error, b.Refusal)
        self.assertEqual(observed, ("w", "anc_end", "guard"))
        self.assertEqual(sum(event[0] == "process" for event in fixture.log), 9)

    def test_one_time_executable_witness_is_not_advertised_as_a_final_exec_recheck(self):
        p = HeldAncestryFixture.UID
        fixture = HeldAncestryFixture((p, 0, 0, 0))
        result, error, _, _ = self.run_guard(fixture)
        self.assertIsNotNone(result)
        self.assertIsNone(error)
        executable = ("open", "exe", 1042, False, True)
        self.assertEqual(fixture.log.count(executable), 1)
        last_executable = fixture.log.index(executable)
        self.assertTrue(any(event[0] == "check" for event in fixture.log[last_executable + 1:]))
        # Only the existing snapshot witness is asserted. A same-PID/credential
        # exec after it is outside this non-atomic trusted-bootstrap contract.


class StartupDiagnosticTests(unittest.TestCase):
    """Inert startup faults; no sudo, source server or host kernel acquisition."""

    def recorder(self, origin="w"):
        value = s.StartupRecorder(origin, active=True)
        return value, patch.object(s, "_STARTUP", value), patch.object(b, "STARTUP_OBSERVER", value)

    def test_literal_origins_closed_kinds_redaction_and_every_line_bound(self):
        errors = [
            (b.Refusal(), "guard"), (AttributeError("PRIVATE_CANARY"), "no_api"),
            (NotImplementedError("PRIVATE_CANARY"), "no_api"),
            (ImportError("PRIVATE_CANARY"), "import"),
            (TypeError("PRIVATE_CANARY"), "bad_arg"), (ValueError("PRIVATE_CANARY"), "bad_arg"),
            (OverflowError("PRIVATE_CANARY"), "bad_arg"),
            (PermissionError(s.errno.EACCES, "PRIVATE_CANARY"), "denied"),
            (OSError(s.errno.EPERM, "PRIVATE_CANARY"), "denied"),
            (OSError(s.errno.ENOENT, "PRIVATE_CANARY"), "missing"),
            (OSError(s.errno.ESRCH, "PRIVATE_CANARY"), "missing"),
            (OSError(s.errno.ENOSYS, "PRIVATE_CANARY"), "unsupported"),
            (OSError(s.errno.ENOPROTOOPT, "PRIVATE_CANARY"), "unsupported"),
            (OSError(s.errno.EOPNOTSUPP, "PRIVATE_CANARY"), "unsupported"),
            *[(OSError(number, "PRIVATE_CANARY"), "resource") for number in
              (s.errno.ENOMEM, s.errno.ENOBUFS, s.errno.EMFILE, s.errno.ENFILE, s.errno.EAGAIN)],
            (OSError(s.errno.EIO, "PRIVATE_CANARY"), "io"),
            (OSError(4095, "PRIVATE_CANARY"), "io"),
            (KeyboardInterrupt("PRIVATE_CANARY"), "cancelled"),
            (RuntimeError("PRIVATE_CANARY"), "other"),
        ]
        self.assertEqual(set(s.STARTUP_KINDS), {expected for _, expected in errors})
        for origin, sites in [("s", s.SUPERVISOR_SITES), ("w", s.WORKER_SITES)]:
            for site in sites + s.PEER_SITES:
                for error, kind in errors:
                    recorder = s.StartupRecorder(origin, active=True)
                    with patch.object(s.os, "write") as output:
                        recorder.fault(site, error)
                    self.assertEqual(output.call_count, 1)
                    line = output.call_args.args[1]
                    self.assertEqual(line, f"DOCKERLENS_NATIVE_PIDS_START: s={origin}_{site} k={kind}\n".encode())
                    self.assertLessEqual(len(line), 64)
                    self.assertTrue(line.isascii())
                    self.assertNotIn(b"PRIVATE_CANARY", line)
        with patch.object(s.os, "write") as output:
            s.StartupRecorder("w", True).fault("parent_uid", b.Refusal())
        self.assertEqual(output.call_args.args[1], b"DOCKERLENS_NATIVE_PIDS_START: s=w_parent_uid k=guard\n")
        for origin, site in [("s", "parent_uid"), ("w", "mon_wait"), ("private", "peer_shape"),
                             ("w", "PRIVATE_CANARY"), ("w", "parent_uid\nPRIVATE_CANARY")]:
            with patch.object(s.os, "write") as output:
                recorder = s.StartupRecorder(origin, True)
                recorder.fault(site, b.Refusal())
                recorder.fault("peer_shape", b.Refusal())
            output.assert_not_called()

    def test_first_fault_precedes_cleanup_and_write_failure_is_not_retried(self):
        recorder, supervisor, boundary = self.recorder()
        with supervisor, boundary, patch.object(s.os, "write", side_effect=OSError("PRIVATE_CANARY")) as output:
            try:
                try:
                    with b.startup_scope("parent_uid"):
                        raise b.Refusal()
                finally:
                    raise PermissionError(s.errno.EPERM, "cleanup")
            except PermissionError:
                pass
            recorder.fault("parent_time", RuntimeError("cleanup"))
        self.assertEqual(output.call_count, 1)
        self.assertEqual(recorder.value, ("w", "parent_uid", "guard"))
        self.assertTrue(recorder.emitted)

    def test_source_initialization_preserves_work_fault_masked_by_close(self):
        recorder, supervisor, boundary = self.recorder()
        budget = unittest.mock.Mock()
        with supervisor, boundary, patch.object(s.os, "write") as output, \
                patch.object(b.ctypes, "CDLL", side_effect=PermissionError(s.errno.EACCES, "work")), \
                patch.object(b.LinuxSource, "close", side_effect=OSError(s.errno.EIO, "cleanup")):
            with self.assertRaises(OSError):
                b.LinuxSource(budget)
        self.assertEqual(recorder.value, ("w", "source_libc", "denied"))
        self.assertEqual(output.call_count, 1)

    def test_locator_initialization_preserves_work_fault_masked_by_close(self):
        recorder, supervisor, boundary = self.recorder()
        def initial(source, budget):
            source.budget, source.proc = budget, 123
        with supervisor, boundary, patch.object(s.os, "write") as output, \
                patch.object(b.LinuxSource, "__init__", initial), \
                patch.object(l, "status_vectors", side_effect=ValueError("PRIVATE_CANARY")), \
                patch.object(l.LocatorSource, "read", return_value=b"private"), \
                patch.object(l.LocatorSource, "close", side_effect=OSError(s.errno.EIO, "cleanup")):
            with self.assertRaises(OSError):
                l.LocatorSource(unittest.mock.Mock())
        self.assertEqual(recorder.value, ("w", "self_status", "bad_arg"))
        self.assertEqual(output.call_count, 1)

    def test_cleanup_only_checked_peer_close_does_not_author_a_record(self):
        recorder, supervisor, boundary = self.recorder()
        with supervisor, boundary, patch.object(s.os, "write") as output, \
                patch.object(s, "peer_socket", return_value=(1, 2, 3, 4)), \
                patch.object(s.os, "close", side_effect=OSError(s.errno.EIO, "cleanup")):
            with self.assertRaises(OSError):
                s.source_server(unittest.mock.Mock(), 100, (1, 2, 3, 9), 10)
        output.assert_not_called()
        self.assertIsNone(recorder.value)

    def test_invalid_ancillary_is_latched_before_failed_rights_cleanup(self):
        recorder, supervisor, boundary = self.recorder()
        channel = s.Channel.__new__(s.Channel)
        channel.wait, channel.budget, channel.stream = unittest.mock.Mock(), unittest.mock.Mock(), unittest.mock.Mock()
        channel.stream.recvmsg.return_value = (b"x", [], socket.MSG_TRUNC, None)
        with supervisor, boundary, patch.object(s.os, "write") as output, \
                patch.object(s, "close_all", side_effect=OSError(s.errno.EIO, "cleanup")):
            with self.assertRaises(OSError):
                channel.receive(1, bootstrap=True)
        self.assertEqual(recorder.value, ("w", "boot_ancillary", "guard"))
        self.assertEqual(output.call_count, 1)

    def test_partial_ready_records_work_but_complete_ready_disables_worker(self):
        from types import SimpleNamespace
        for partial in (False, True):
            with self.subTest(partial=partial):
                recorder, supervisor, boundary = self.recorder()
                channel = s.Channel.__new__(s.Channel)
                channel.wait, channel.budget, channel.stream = unittest.mock.Mock(), unittest.mock.Mock(), unittest.mock.Mock()
                channel.receive = unittest.mock.Mock(return_value=(b"BFPIDS1\n", [17]))
                channel.stream.send.side_effect = [3, OSError(s.errno.EIO, "private")] if partial else [8]
                with supervisor, boundary, patch.object(s.os, "write") as output, \
                        patch.object(s.os, "fstat", return_value=SimpleNamespace(st_mode=0o40700, st_uid=5)), \
                        patch.object(s.fcntl, "fcntl", return_value=s.fcntl.FD_CLOEXEC), patch.object(s, "close_all"):
                    if partial:
                        with self.assertRaises(OSError):
                            channel.bootstrap(5)
                        self.assertEqual(recorder.value, ("w", "ready_send", "io"))
                        self.assertTrue(recorder.active)
                    else:
                        self.assertEqual(channel.bootstrap(5), 17)
                        self.assertFalse(recorder.active)
                        recorder.fault("parent_uid", b.Refusal())
                        output.assert_not_called()

    def test_successful_nested_scope_does_not_leave_stale_site(self):
        recorder, supervisor, boundary = self.recorder()
        with supervisor, boundary, patch.object(s.os, "write") as output:
            with self.assertRaises(b.Refusal):
                with b.startup_scope("parent_uid"):
                    with b.startup_scope("proc_status"):
                        pass
                    raise b.Refusal()
        self.assertEqual(recorder.value, ("w", "parent_uid", "guard"))
        self.assertEqual(output.call_count, 1)

    def test_read_work_is_latched_before_close_but_cleanup_only_stays_silent(self):
        for work_failure in (False, True):
            recorder, supervisor, boundary = self.recorder()
            source = b.LinuxSource.__new__(b.LinuxSource)
            source.open = unittest.mock.Mock(return_value=7)
            source.read_fd = unittest.mock.Mock(return_value=b"ok")
            if work_failure:
                source.read_fd.side_effect = PermissionError(s.errno.EACCES, "work")
            source.close_fd = unittest.mock.Mock(side_effect=OSError(s.errno.EIO, "cleanup"))
            with supervisor, boundary, patch.object(s.os, "write") as output, patch.object(b, "fs_magic", return_value=b.PROC_MAGIC):
                with self.assertRaises(OSError):
                    source.read(3, "fixed", 1024)
            self.assertEqual(output.call_count, int(work_failure))
            self.assertEqual(recorder.value, ("w", "source_read", "denied") if work_failure else None)

    def test_source_server_preserves_parent_work_before_final_source_close(self):
        recorder, supervisor, boundary = self.recorder()
        source = unittest.mock.Mock()
        source.read.side_effect = PermissionError(s.errno.EACCES, "work")
        source.close.side_effect = OSError(s.errno.EIO, "cleanup")
        with supervisor, boundary, patch.object(s.os, "write") as output, \
                patch.object(s, "peer_socket", return_value=(9, 10, 11, 12)), patch.object(s.os, "close"), \
                patch.object(l, "RuntimeBudget"), patch.object(l, "LocatorSource", return_value=source), patch.object(l, "live"):
            with self.assertRaises(b.Refusal):
                s.source_server(unittest.mock.Mock(), 100, (9, 10, 11, 13), 20)
        self.assertEqual(recorder.value, ("w", "parent_stat", "denied"))
        self.assertEqual(output.call_count, 1)

    def test_recorder_construction_failure_is_silent_and_never_retried(self):
        recorder = s.StartupRecorder("w", True)
        with patch.object(recorder, "kind", side_effect=RuntimeError("PRIVATE_CANARY")), patch.object(s.os, "write") as output:
            recorder.fault("parent_uid", b.Refusal())
            recorder.fault("parent_time", b.Refusal())
        output.assert_not_called()
        self.assertTrue(recorder.seen)
        self.assertIsNone(recorder.value)

    def test_nested_constructor_read_cleanup_is_not_self_stat_or_status_work(self):
        for locator in (False, True):
            recorder, supervisor, boundary = self.recorder()
            error = OSError(s.errno.EIO, "PRIVATE_CLEANUP")
            original_args = error.args
            def initial(source, budget):
                source.budget, source.proc = budget, 3
            with supervisor, boundary, patch.object(s.os, "write") as output, \
                    patch.object(b, "fs_magic", return_value=b.PROC_MAGIC), \
                    patch.object(b.ctypes, "CDLL"), patch.object(b.LinuxSource, "open", return_value=3), \
                    patch.object(b.LinuxSource, "read_fd", return_value=b"ok"), \
                    patch.object(b.LinuxSource, "close_fd", side_effect=error), patch.object(b.LinuxSource, "close"):
                if locator:
                    with patch.object(b.LinuxSource, "__init__", initial):
                        with self.assertRaises(OSError) as caught:
                            l.LocatorSource(unittest.mock.Mock())
                else:
                    with self.assertRaises(OSError) as caught:
                        b.LinuxSource(unittest.mock.Mock())
            self.assertIs(caught.exception, error)
            self.assertEqual(error.args, original_args)
            self.assertIsNone(recorder.value)
            self.assertFalse(recorder.seen)
            output.assert_not_called()

    def test_nested_reopened_close_only_is_not_proc_check_work(self):
        from types import SimpleNamespace
        for work_failure in (False, True):
            recorder, supervisor, boundary = self.recorder()
            error = OSError(s.errno.EIO, "PRIVATE_CLEANUP")
            original_args = error.args
            source = b.LinuxSource.__new__(b.LinuxSource)
            source.budget = unittest.mock.Mock()
            source.proc = 3
            source.read = unittest.mock.Mock(side_effect=[
                b"9 (comm) S " + b"0 " * 18 + b"10\n", b"0::/\n",
                b"Pid:\t9\nTgid:\t9\nUid:\t5\t5\t5\t5\nNSpid:\t9\n",
            ])
            source.open = unittest.mock.Mock(side_effect=[21, 22, 23, 24, 25])
            source.fd_mount_id = unittest.mock.Mock(return_value=1)
            source.close_fd = unittest.mock.Mock(side_effect=error)
            proc = SimpleNamespace(pidfd=2, pid=9, start=10, directory=3, membership=(),
                status=((9,), (5, 5, 5, 5), (9,)), identity=((1, 1), ((1, 1), 1), ((1, 1),) * 3))
            if work_failure:
                proc.identity = ()
            with supervisor, boundary, patch.object(s.os, "write") as output, \
                    patch.object(b.select, "select", return_value=([], [], [])), patch.object(b, "identity", return_value=(1, 1)):
                with self.assertRaises(OSError) as caught:
                    with b.startup_scope("proc_check"):
                        source.check_process(proc)
            self.assertIs(caught.exception, error)
            self.assertEqual(error.args, original_args)
            self.assertEqual(source.close_fd.call_count, 1)
            self.assertEqual(output.call_count, int(work_failure))
            self.assertEqual(recorder.value, ("w", "proc_identity", "guard") if work_failure else None)
            if not work_failure:
                self.assertFalse(recorder.seen)

    def test_failed_cleanup_marking_disables_observation_without_replacing_exception(self):
        class Unmarkable(OSError):
            @property
            def _dockerlens_startup_cleanup(self):
                return False
        for first_work in (False, True):
            recorder, supervisor, boundary = self.recorder()
            error = Unmarkable(s.errno.EIO, "PRIVATE_CLEANUP")
            original_args = error.args
            with supervisor, boundary, patch.object(s.os, "write") as output:
                if first_work:
                    recorder.fault("parent_uid", b.Refusal())
                with self.assertRaises(Unmarkable) as caught:
                    with b.startup_scope("self_stat"):
                        with b.startup_cleanup():
                            raise error
                recorder.fault("parent_time", b.Refusal())
            self.assertIs(caught.exception, error)
            self.assertEqual(error.args, original_args)
            self.assertFalse(recorder.active)
            self.assertEqual(output.call_count, int(first_work))
            self.assertEqual(recorder.value, ("w", "parent_uid", "guard") if first_work else None)

    def test_failed_cleanup_marker_lookup_is_unobserved_without_new_failure(self):
        class Uninspectable(OSError):
            @property
            def _dockerlens_startup_cleanup(self):
                raise RuntimeError("PRIVATE_CANARY")
        recorder = s.StartupRecorder("w", True)
        with patch.object(s.os, "write") as output:
            recorder.fault("parent_uid", Uninspectable(s.errno.EIO, "private"))
            recorder.fault("parent_time", b.Refusal())
        output.assert_not_called()
        self.assertFalse(recorder.active)
        self.assertIsNone(recorder.value)

    def test_fork_child_resets_inherited_supervisor_role_and_latch(self):
        class ExitChild(BaseException):
            pass
        recorder, supervisor, boundary = self.recorder("s")
        with patch.object(s.os, "write"):
            recorder.fault("peer_shape", b.Refusal())
        def source(*_args):
            self.assertEqual((recorder.origin, recorder.seen), ("w", False))
            recorder.fault("parent_uid", b.Refusal())
        stream = unittest.mock.Mock()
        with supervisor, boundary, patch.object(s.os, "write") as output, \
                patch.object(s.os, "geteuid", return_value=0), patch.object(s.time, "monotonic_ns", return_value=1), \
                patch.object(s, "peer_socket", return_value=(9, 10, 11, 12)), \
                patch.object(s.os, "pipe2", return_value=(13, 14)), patch.object(s.signal, "pthread_sigmask", return_value=set()), \
                patch.object(s.os, "getpid", return_value=20), patch.object(s.os, "getppid", return_value=20), \
                patch.object(s.os, "fork", return_value=0), patch.object(s.os, "close"), patch.object(s.os, "setpgid"), \
                patch.object(s.boundary.ctypes, "CDLL") as libc, patch.object(s.os, "read", return_value=b"G"), \
                patch.object(s, "source_server", side_effect=source), patch.object(s.os, "_exit", side_effect=ExitChild), \
                patch.object(s.os, "waitpid", return_value=(0, 0)), patch.object(s.os, "killpg"):
            libc.return_value.prctl.return_value = 0
            with self.assertRaises(ExitChild):
                s.supervise(stream, 180_000_000_001)
        self.assertEqual(output.call_count, 1)
        self.assertEqual(output.call_args.args[1], b"DOCKERLENS_NATIVE_PIDS_START: s=w_parent_uid k=guard\n")

    def test_supervisor_remains_site_observer_after_worker_ready(self):
        worker, supervisor = s.StartupRecorder("w", True), s.StartupRecorder("s", True)
        worker.stop()
        with patch.object(s.os, "write") as output:
            worker.fault("ready_send", OSError(s.errno.EIO, "private"))
            supervisor.fault("mon_wait", OSError(s.errno.EIO, "private"))
        self.assertEqual(output.call_count, 1)
        self.assertEqual(output.call_args.args[1], b"DOCKERLENS_NATIVE_PIDS_START: s=s_mon_wait k=io\n")

    def test_derived_monitor_result_does_not_invent_a_startup_fault(self):
        from types import SimpleNamespace
        for result in (0, 1):
            with self.subTest(result=result), patch.object(s.os, "write") as output, \
                    patch.object(s.os, "fstat", return_value=SimpleNamespace(st_mode=0o140600)), \
                    patch.object(s.socket, "socket") as stream, patch.object(s, "supervise", return_value=result):
                self.assertEqual(s.main(["supervise", "123"]), result)
                self.assertIsNone(s._STARTUP.value)
                self.assertFalse(s._STARTUP.active)
                self.assertEqual(output.call_count, result)
                if result:
                    self.assertEqual(output.call_args.args[1], b"native-pids-supervisor: refused\n")

if __name__ == "__main__":
    unittest.main()
