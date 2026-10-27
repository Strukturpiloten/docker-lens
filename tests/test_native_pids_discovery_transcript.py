"""Initial mixed-topology authored envelope, using the existing real IPC loop.

Physical temp-file reads/opens/getdents and socketpair/fork/framing are real.
Kernel filesystem/mount/pidfd/namespace, source clock and Engine facts remain simulated by
the existing fixture. Authored fdinfo facts are read through actual charged
LinuxSource.fd_mount_id; fixture construction/writes are not source reads.
Authored short fdinfo content and regular-file read shapes do not establish
native procfs byte counts, latency, failure behavior or deadline fit.
One daemon task inhabits a threaded subtree; measured workers remain ordinary.
This is not multi-threaded-daemon or fully-threaded-worker/proof-v2 coverage,
native authentication, universal/512-leader fit, or production/Rust-owner wiring.
"""

import fcntl
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import native_pids_discovery as discovery
import test_native_pids_supervisor as existing


locator, boundary, supervisor = existing.l, existing.b, existing.s
require = boundary.require


class TypedDiscoveryTranscriptTests(unittest.TestCase):
    def test_initial_mixed_topology_reuses_complete_original_owner_transcript(self):
        outer_test = self

        class Runner(existing.RootFactoryTests):
            def run_factory(self, operation, *, rootful=False):
                outer_test.assertFalse(rootful)

                def adapted(tree, session, channel, request, calls):
                    # No ordinary populated parent with enabled domain children.
                    tree.make_group(tree.cg / "owned/init.scope", "max", [100])
                    (tree.proc / "100/cgroup").write_text("0::/owned/init.scope\n")
                    tree.make_group(tree.cg / "owned/daemon.scope", "max", [110])
                    (tree.cg / "owned/daemon.scope/cgroup.type").write_text("domain threaded\n")
                    (tree.cg / "owned/daemon.scope/cgroup.threads").write_text("")
                    tree.make_group(tree.cg / "owned/daemon.scope/member", "max", [110])
                    (tree.cg / "owned/daemon.scope/member/cgroup.type").write_text("threaded\n")
                    (tree.cg / "owned/daemon.scope/member/cgroup.procs").write_text("")
                    (tree.proc / "110/cgroup").write_text("0::/owned/daemon.scope/member\n")
                    for name in ("cgroup.procs", "cgroup.threads"):
                        (tree.cg / "owned" / name).write_text("")
                    (tree.cg / "owned/pids.current").write_text("8\n")
                    source = tree.source
                    initial_unowned_reservations = source.budget.fds - len(source.owned)
                    failed_open_reservations = []
                    original_open, original_release, original_close = source.open, source.release_since, source.close
                    original_response = supervisor.Channel.response
                    runtime = None
                    transfers, retired = {}, set()
                    discoveries = []
                    seal_releases, source_closes = [], []
                    retiring = False

                    def checked_open(name, parent=None, **options):
                        if name == "cgroup.procs" and parent is not None:
                            self.assertNotEqual(os.readlink("/proc/self/fd/" + str(parent)),
                                                str(tree.cg / "owned/daemon.scope/member"))
                        try:
                            return original_open(name, parent, **options)
                        except OSError:
                            failed_open_reservations.append(True)
                            raise

                    def charged_mount_id(fd):
                        # Same declared mount-ID fact as the original fixture,
                        # now decoded from a real bounded/charged fdinfo read.
                        directory = tree.proc / "self/fdinfo"
                        directory.mkdir(exist_ok=True)
                        (directory / str(fd)).write_text("pos:\t0\nflags:\t0100000\nmnt_id:\t10\n")
                        return boundary.LinuxSource.fd_mount_id(source, fd)

                    def retire(name):
                        nonlocal retiring
                        if name not in transfers or name in retired:
                            return
                        retired.add(name)  # no retry after uncertain close
                        previous_retiring, retiring = retiring, True
                        try:
                            transfers[name].close()
                        finally:
                            retiring = previous_retiring

                    def release_since(previous):
                        if not retiring and runtime is not None and previous is runtime.retained:
                            # Original seal: recheck and six snapshots already
                            # finished; its generic release has not started.
                            self.assertFalse(runtime.sealed)
                            self.assertEqual(len(runtime.bound), 6)
                            self.assertEqual(seal_releases, [])
                            seal_releases.append(True)
                            first = None
                            try:
                                retire("workers")
                            except BaseException as error:
                                first = error
                            try:
                                original_release(previous)
                            except BaseException as later:
                                if first is not None:
                                    raise first from later
                                raise
                            if first is not None:
                                raise first
                            return
                        return original_release(previous)

                    def close():
                        first = None
                        for name in ("workers", "peer"):
                            try:
                                retire(name)
                            except BaseException as error:
                                if first is None:
                                    first = error
                        try:
                            original_close()  # always attempt original ROOT cleanup
                        except BaseException as later:
                            if first is not None:
                                raise first from later
                            raise
                        if first is not None:
                            raise first
                        source_closes.append(True)

                    def discover(mode, consume):
                        discoveries.append(mode)
                        return discovery.discover(source, runtime.outer_group, mode, consume)

                    def bind_peer(actual_runtime, pid, uid, original_peer_pidfd):
                        nonlocal runtime
                        runtime = actual_runtime
                        if runtime.daemon is not None:
                            require(pid == runtime.daemon.pid)
                            runtime.check_daemon()
                            return
                        runtime.check_outer()
                        previous = set(source.owned)
                        locator.live(original_peer_pidfd)
                        outer_namespace = boundary.identity(runtime.outer.namespaces[0])
                        def consume(lease):
                            record = next((record for record in lease.candidates if record.pid == pid), None)
                            require(record is not None)
                            with lease.acquire(record) as candidate:
                                require(candidate.status[1] == (uid,) * 4
                                        and outer_namespace in candidate.namespace_chain)
                                lease.select(discovery.Role.PEER, candidate)
                        transfer = discover(discovery.Mode.PEER, consume)
                        transfers["peer"] = transfer
                        selected = transfer.selections[0].candidate
                        process = selected.process
                        executable = runtime.executable(process)
                        executable_fd = source.open("exe", process.directory, magic=True)
                        require(boundary.identity(executable_fd) == executable)
                        source.budget.fd()
                        peer = source.own(fcntl.fcntl(original_peer_pidfd, fcntl.F_DUPFD_CLOEXEC, 3))
                        locator.live(peer)
                        runtime.daemon, runtime.daemon_chain = process, selected.namespace_chain
                        runtime.daemon_executable, runtime.daemon_executable_fd = executable, executable_fd
                        runtime.daemon_peer_pidfd = peer
                        runtime.check_daemon()
                        transfer.release_witnesses()
                        runtime.retained.update(source.owned - previous)
                        self.assertEqual(runtime.outer.membership, ("owned", "init.scope"))
                        self.assertEqual(runtime.outer_group.membership, ("owned",))

                    def locate_batch(actual_runtime, slots):
                        require(actual_runtime is runtime)
                        try:
                            require(not runtime.failed and not runtime.sealed and not runtime.bound
                                    and type(slots) is dict and tuple(slots) == locator.ORDER
                                    and len(set(slots.values())) == 6)
                            before = {slot: runtime.inspect(cid) for slot, cid in slots.items()}
                            if runtime.slot_label is not None:
                                require(all(dict(before[slot][3]).get(runtime.slot_label) == slot for slot in locator.ORDER))
                            daemon_ns = boundary.identity(runtime.daemon.namespaces[0])
                            seen = set()
                            def consume(lease):
                                for record in lease.candidates:
                                    with lease.acquire(record) as candidate:
                                        chain, vector = candidate.namespace_chain, candidate.status[2]
                                        if daemon_ns not in chain:
                                            continue
                                        index = chain.index(daemon_ns)
                                        for slot in locator.ORDER:
                                            if vector[index] == before[slot][0]:
                                                require(index < len(chain) - 1 and vector[-1] == 1)
                                                if slot in seen:
                                                    raise locator.LocatorRefusal("AmbiguousMatch")
                                                seen.add(slot)
                                                lease.select(discovery.Role(slot), candidate)
                                if seen != set(locator.ORDER):
                                    raise locator.LocatorRefusal("NoMatch")
                            transfer = discover(discovery.Mode.WORKERS, consume)
                            transfers["workers"] = transfer
                            result = {}
                            for selected in transfer.selections:
                                slot = selected.role.value
                                candidate = selected.candidate
                                process = candidate.process
                                group = source.group(process)  # graph is closed
                                source.descendant(runtime.outer_group, group)
                                source.leaf(group)
                                maximum, current, _events = source.values(group)
                                expected = "max" if slot.endswith("unlimited") else (16 if slot.endswith("16") else 64)
                                require(maximum == expected and current == 1)
                                require(selected.local_witness is selected.coverage_witness
                                        and group.identities[-1] == selected.local_witness.identity
                                        and group.membership == selected.local_witness.membership == process.membership)
                                result[slot] = locator.RuntimeBoundProcess(slot, slots[slot], process, group,
                                                                         candidate.namespace_chain, before[slot])
                            require(len({item.process.pid for item in result.values()}) == 6
                                    and len({item.group.identities[-1] for item in result.values()}) == 6)
                            transfer.release_witnesses()
                            for item in result.values():
                                require(runtime.inspect(item.container_id) == item.inspect_facts)
                                source.check_process(item.process)
                                source.check_group(item.group)
                            runtime.check_daemon()
                            runtime.bound = result
                            return result
                        except locator.LocatorRefusal:
                            runtime.failed = True
                            raise
                        except (Exception, KeyboardInterrupt):
                            runtime.failed = True
                            raise locator.LocatorRefusal() from None

                    def response(actual_channel, value):
                        if value.get("op") != "OuterFinalize":
                            return original_response(actual_channel, value)
                        self.assertEqual(discoveries, [discovery.Mode.PEER, discovery.Mode.WORKERS])
                        self.assertEqual(seal_releases, [True])
                        self.assertEqual(source_closes, [True])
                        self.assertEqual(retired, {"peer", "workers"})
                        self.assertEqual(source.owned, set())
                        self.assertEqual(source.process_times, {})
                        self.assertTrue(runtime.sealed)
                        self.assertEqual(runtime.bound, {})
                        self.assertEqual({slot: len(phases) for slot, phases in session.measurements.samples.items()},
                                         {slot: 4 for slot in locator.ORDER})
                        self.assertEqual(value["reservations"], {"inspect_calls_reserved": 24,
                            "inspect_body_bytes_reserved": 786432, "runtime_probe_calls_reserved": 1,
                            "runtime_probe_body_bytes_reserved": 4096})
                        ledger = value["source_ledger"]
                        self.assertEqual(ledger, source.budget.ledger(0))
                        self.assertEqual(source.budget.frames, 55)
                        self.assertLessEqual(source.budget.bytes, 32 * 1024 * 1024)
                        self.assertLessEqual(source.budget.reads, 65536)
                        self.assertLessEqual(source.budget.opens, 32768)
                        self.assertLessEqual(source.budget.peak_fds, 256)
                        # Original Channel reserves three transient ancillary
                        # slots outside Source.owned. Failed open reservations,
                        # if any, also remain charged; neither is refunded here.
                        self.assertEqual(source.budget.fds,
                                         initial_unowned_reservations + 3 + len(failed_open_reservations))
                        self.assertEqual(initial_unowned_reservations, locator.FIXED_FD_RESERVE)
                        self.assertLessEqual(value["reservations"]["inspect_calls_reserved"]
                                             + value["reservations"]["runtime_probe_calls_reserved"], 300)
                        self.assertLessEqual(value["reservations"]["inspect_body_bytes_reserved"]
                                             + value["reservations"]["runtime_probe_body_bytes_reserved"], 2 * 1024 * 1024)
                        original_response(actual_channel, value)
                        frame = len(json.dumps(value, separators=(",", ":"), sort_keys=True).encode()) + 4
                        self.assertEqual(source.budget.output, ledger["output_reserved_before_final"] + frame)
                        self.assertLessEqual(source.budget.output, 65536)
                        print("typed_discovery_transcript_metrics=" + json.dumps({
                            "discoveries": len(discoveries), "samples": 24, "owner_requests": 30,
                            "api_acknowledgments": 25, "api_reserved_bytes": 790528,
                            "source_reserved_bytes": source.budget.bytes, "source_read_reservations": source.budget.reads,
                            "fd_open_reservations": source.budget.opens, "fd_peak_reservations": source.budget.peak_fds,
                            "remaining_fd_reservations": source.budget.fds,
                            "failed_open_reservations": len(failed_open_reservations),
                            "output_bytes": source.budget.output, "input_frames": source.budget.frames,
                            "owned_remaining": len(source.owned)}, sort_keys=True), flush=True)

                    def checked_response(actual_channel, value):
                        try:
                            return response(actual_channel, value)
                        except BaseException as error:
                            trace = error.__traceback__
                            line = 0
                            while trace is not None:
                                if trace.tb_frame.f_code.co_filename == __file__:
                                    line = trace.tb_lineno
                                trace = trace.tb_next
                            print("typed_discovery_transcript_check_failure=" + json.dumps({
                                "line": line, "fd_reservations": source.budget.fds,
                                "initial_unowned_reservations": initial_unowned_reservations,
                                "failed_open_reservations": len(failed_open_reservations),
                                "source_reads": source.budget.reads, "source_bytes": source.budget.bytes,
                                "fd_peak": source.budget.peak_fds, "output_bytes": source.budget.output,
                                "input_frames": source.budget.frames, "owned_remaining": len(source.owned)},
                                sort_keys=True), flush=True)
                            raise

                    with patch.object(source, "open", checked_open), patch.object(source, "fd_mount_id", charged_mount_id), \
                            patch.object(source, "release_since", release_since), patch.object(source, "close", close), \
                            patch.object(locator.RuntimeLocator, "_bind_peer", bind_peer), \
                            patch.object(locator.RuntimeLocator, "locate_batch", locate_batch), \
                            patch.object(supervisor.Channel, "response", checked_response):
                        return operation(tree, session, channel, request, calls)

                return super().run_factory(adapted, rootful=rootful)

        # Reuse its actual socketpair/fork/server/30-request/25-ack loop verbatim.
        Runner().test_full_factory_transcript_actual_ipc_has_30_owner_requests_and_25_debit_acks()


if __name__ == "__main__":
    unittest.main()
