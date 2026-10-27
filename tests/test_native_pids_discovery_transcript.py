"""Authored typed production-source owner transcripts over real file/IPC I/O.

Reads, opens, getdents, socketpair, fork and framing are real. The existing
fixture simulates filesystem/mount/pidfd/namespace facts, source clock and Engine.
Fixture writes and independent oracle reads are outside source accounting. Short
regular-file proc/fdinfo models establish neither native byte counts nor latency.
This is no native qualification, Rust proof publication or universal topology fit.
"""

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

# Literal expectations belong to the authored fixture, not the production planner.
LEAVES = {
    "cli16": ("cli16", "domain"),
    "cli64": ("thread-root/cli64", "threaded"),
    "cli_unlimited": ("domain-branch/cli_unlimited", "domain"),
    "rendered16": ("rendered16", "domain threaded"),
    "rendered64": ("thread-root/middle/rendered64", "threaded"),
    "rendered_unlimited": ("domain-branch/rendered_unlimited", "domain threaded"),
}
CHAINS = {
    "cli16": ("domain", "domain", "domain"),
    "cli64": ("threaded", "domain threaded", "domain", "domain"),
    "cli_unlimited": ("domain", "domain", "domain", "domain"),
    "rendered16": ("domain threaded", "domain", "domain"),
    "rendered64": ("threaded", "threaded", "domain threaded", "domain", "domain"),
    "rendered_unlimited": ("domain threaded", "domain", "domain", "domain"),
}
OUTER_INDEX = {"cli16": 1, "cli64": 2, "cli_unlimited": 2,
               "rendered16": 1, "rendered64": 3, "rendered_unlimited": 2}


def _typed_kernel_model(tree, case, daemon_tasks):
    """Translate only the old loop's fixture writes; Source sees real paths."""
    case.assertIn(daemon_tasks, (1, 3))
    raw_write = Path.write_text
    hierarchy = tree.cg
    above = hierarchy / "above"
    tree.make_group(above, 2048, [])
    (hierarchy / "owned").rename(above / "owned")
    # Existing guest mount and parent-loop fixture closures read this dynamically.
    # self/mountinfo still names the original actual hierarchy root.
    tree.cg = above
    outer = above / "owned"
    for name in ("cgroup.procs", "cgroup.threads"):
        raw_write(outer / name, "")
    tree.make_group(outer / "init.scope", "max", [100])
    raw_write(tree.proc / "100/cgroup", "0::/above/owned/init.scope\n")
    mountinfo = tree.proc / "100/mountinfo"
    raw_write(mountinfo, mountinfo.read_text().replace(" /owned /sys/fs/cgroup ",
                                                   " /above/owned /sys/fs/cgroup "))
    tree.make_group(outer / "domain-branch", "max", [])
    tree.make_group(outer / "thread-root", "max", [])
    raw_write(outer / "thread-root/cgroup.type", "domain threaded\n")
    tree.make_group(outer / "thread-root/middle", "max", [])
    raw_write(outer / "thread-root/middle/cgroup.type", "threaded\n")
    directories = {}
    for slot, (relative, kind) in LEAVES.items():
        original, directory = outer / slot, outer / relative
        if original != directory:
            original.rename(directory)
        directories[slot] = directory
        raw_write(directory / "cgroup.type", kind + "\n")
        raw_write(tree.proc / str(200 + locator.ORDER.index(slot)) / "cgroup",
                  "0::/above/owned/" + relative + "\n")
        if kind == "threaded":
            raw_write(directory / "cgroup.procs", "")
    daemon = outer / "daemon.scope"
    tree.make_group(daemon, "max", [110])
    raw_write(daemon / "cgroup.type", "domain threaded\n")
    raw_write(daemon / "cgroup.threads", "")
    tree.make_group(daemon / "member", "max", [110])
    raw_write(daemon / "member/cgroup.type", "threaded\n")
    raw_write(daemon / "member/cgroup.procs", "")
    raw_write(tree.proc / "110/cgroup", "0::/above/owned/daemon.scope/member\n")
    members = {"member": (110,)}
    vectors = {110: (110, 2, 1)}
    locations = {110: "member"}
    if daemon_tasks == 3:
        members = {"member": (110, 111), "sibling": (112,)}
        vectors.update({111: (111, 3, 2), 112: (112, 4, 3)})
        locations.update({111: "member", 112: "sibling"})
        for pid in (111, 112):
            tree.make_process(pid, "daemon", vectors[pid],
                              "above/owned/daemon.scope/" + locations[pid], 1000)
            (tree.proc / str(pid) / "exe").unlink()
            (tree.proc / str(pid) / "exe").symlink_to(tree.rootfs / "usr/local/bin/dockerd")
        tree.make_group(daemon / "sibling", "max", [112])
        raw_write(daemon / "sibling/cgroup.type", "threaded\n")
        raw_write(daemon / "sibling/cgroup.procs", "")
    tasks = tree.proc / "110/task"
    tasks.mkdir()
    for pid, vector in vectors.items():
        raw_write(tree.proc / str(pid) / "status",
                  f"Pid: {pid}\nTgid: 110\nUid: 1000 1000 1000 1000\n"
                  f"NSpid: {' '.join(map(str, vector))}\nNStgid: 110 2 1\nThreads: {daemon_tasks}\n")
        (tasks / str(pid)).symlink_to(tree.proc / str(pid), target_is_directory=True)
    for pid in (100, *range(200, 206)):
        status = tree.proc / str(pid) / "status"
        raw_write(status, status.read_text() + "Threads: 1\n")
    for name, tids in members.items():
        raw_write(daemon / name / "cgroup.threads", "".join(f"{pid}\n" for pid in tids))
        raw_write(daemon / name / "pids.current", f"{len(tids)}\n")
    raw_write(daemon / "pids.current", f"{daemon_tasks}\n")

    def ids(path):
        result = tuple(int(value) for value in path.read_text().splitlines())
        case.assertEqual(len(result), len(set(result)))
        case.assertTrue(all(0 < value < 4194304 for value in result))
        return result

    def fields(pid):
        result = {}
        for row in (tree.proc / str(pid) / "status").read_text().splitlines():
            name, value = row.split(":", 1)
            case.assertNotIn(name, result)
            result[name] = tuple(int(part) for part in value.split())
        return result

    def worker_sum():
        return sum(int((directory / "pids.current").read_text()) for directory in directories.values())

    def synchronize():
        # Kernel hierarchy aggregates, distinct from source I/O and reservations.
        for relative, slots in (("domain-branch", ("cli_unlimited", "rendered_unlimited")),
                                ("thread-root", ("cli64", "rendered64")),
                                ("thread-root/middle", ("rendered64",))):
            directory = outer / relative
            raw_write(directory / "pids.current", str(sum(int((directories[slot] / "pids.current").read_text())
                                                         for slot in slots)) + "\n")
            event = sum(int((directories[slot] / "pids.events.local").read_text().split()[1]) for slot in slots)
            raw_write(directory / "pids.events", f"max {event}\n")
            if relative == "thread-root":
                raw_write(directory / "cgroup.procs", "".join(f"{pid}\n" for slot in slots
                                                           for pid in ids(directories[slot] / "cgroup.threads")))
        current = 1 + daemon_tasks + worker_sum()
        event = sum(int((directory / "pids.events.local").read_text().split()[1])
                    for directory in directories.values())
        for directory in (outer, above):
            raw_write(directory / "pids.current", f"{current}\n")
            raw_write(directory / "pids.events", f"max {event}\n")
        raw_write(hierarchy / "pids.current", f"{992 + current}\n")
        raw_write(hierarchy / "pids.events", f"max {event}\n")
        raw_write(tree.proc / "loadavg", f"0.00 0.00 0.00 1/{992 + current} 200\n")

    def check():
        case.assertEqual(ids(outer / "cgroup.procs"), ())
        case.assertEqual(ids(outer / "cgroup.threads"), ())
        case.assertEqual((outer / "cgroup.type").read_text(), "domain\n")
        case.assertEqual(ids(outer / "init.scope/cgroup.threads"), (100,))
        case.assertEqual((tree.proc / "100/cgroup").read_text(), "0::/above/owned/init.scope\n")
        case.assertEqual((daemon / "cgroup.type").read_text(), "domain threaded\n")
        case.assertEqual(ids(daemon / "cgroup.procs"), (110,))
        case.assertEqual(ids(daemon / "cgroup.threads"), ())
        case.assertEqual(int((daemon / "pids.current").read_text()), daemon_tasks)
        case.assertEqual({int(path.name) for path in tasks.iterdir()}, set(vectors))
        for name, expected in members.items():
            case.assertEqual(ids(daemon / name / "cgroup.threads"), expected)
            case.assertEqual(ids(daemon / name / "cgroup.procs"), ())
            case.assertEqual(int((daemon / name / "pids.current").read_text()), len(expected))
            case.assertEqual((daemon / name / "cgroup.type").read_text(), "threaded\n")
        for pid, expected_vector in vectors.items():
            status = fields(pid)
            case.assertEqual(status["Pid"], (pid,))
            case.assertEqual(status["Tgid"], (110,))
            case.assertEqual(status["Uid"], (1000, 1000, 1000, 1000))
            case.assertEqual(status["Threads"], (daemon_tasks,))
            case.assertEqual(status["NSpid"], expected_vector)
            case.assertEqual(status["NStgid"], (110, 2, 1))
            case.assertEqual(boundary.start_from_stat((tree.proc / str(pid) / "stat").read_bytes(), pid), pid * 10)
            case.assertEqual((tree.proc / str(pid) / "cgroup").read_text(),
                             "0::/above/owned/daemon.scope/" + locations[pid] + "\n")
            case.assertEqual((tasks / str(pid)).resolve(), tree.proc / str(pid))
            case.assertEqual(os.readlink(tree.proc / str(pid) / "ns/pid"), str(tree.ns / "daemon"))
        all_tids = {100, *vectors}
        for slot, directory in directories.items():
            relative, kind = LEAVES[slot]
            tids = ids(directory / "cgroup.threads")
            case.assertFalse(all_tids.intersection(tids))
            all_tids.update(tids)
            case.assertEqual(ids(directory / "cgroup.procs"), () if kind == "threaded" else tids)
            case.assertEqual((directory / "cgroup.type").read_text(), kind + "\n")
            case.assertEqual(len(tids), int((directory / "pids.current").read_text()))
            case.assertIn(len(tids), (1, 16) if slot.endswith("16") else (1, 33))
            for pid in tids:
                status = fields(pid)
                case.assertEqual(status["Pid"], (pid,))
                case.assertEqual(status["Tgid"], (pid,))
                case.assertEqual(status["Threads"], (1,))
                case.assertEqual(status["NSpid"], status["NStgid"])
                case.assertEqual((tree.proc / str(pid) / "cgroup").read_text(), "0::/above/owned/" + relative + "\n")
        current = 1 + daemon_tasks + worker_sum()
        case.assertEqual(int((outer / "pids.current").read_text()), current)
        case.assertEqual(int((above / "pids.current").read_text()), current)
        case.assertEqual((tree.proc / "loadavg").read_text().split()[3], f"1/{992 + current}")
        for name in ("pids.max", "cgroup.type", "cgroup.events"):
            case.assertFalse((hierarchy / name).exists())
        for relative in ("init.scope", "daemon.scope", "daemon.scope/member", "domain-branch",
                         "thread-root", "thread-root/middle"):
            case.assertEqual((outer / relative / "pids.events.local").read_text(), "max 0\n")

    def write(path, data, *args, **kwargs):
        # The original parent's requests and literal phase counts are untouched.
        if path == outer / "pids.current":
            case.assertEqual(data, f"{2 + worker_sum()}\n")
            synchronize()
            return len(data)
        if path == tree.proc / "loadavg":
            case.assertEqual(data, f"0.00 0.00 0.00 1/{994 + worker_sum()} 200\n")
            synchronize()
            return len(data)
        if path == outer / "pids.events":
            event = sum(int((directory / "pids.events.local").read_text().split()[1]) for directory in directories.values())
            case.assertEqual(data, f"max {event}\n")
            synchronize()
            return len(data)
        for slot, directory in directories.items():
            if path.parent == outer / slot:
                if path.name == "cgroup.procs" and LEAVES[slot][1] == "threaded":
                    case.assertEqual(data, (directory / "cgroup.threads").read_text())
                    return len(data)
                path = directory / path.name
                break
        if path.name == "cgroup" and path.parent.parent == tree.proc and path.parent.name.isdigit():
            for slot, (relative, _kind) in LEAVES.items():
                if data == "0::/owned/" + slot + "\n":
                    data = "0::/above/owned/" + relative + "\n"
                    break
        if path.name == "status" and path.parent.parent == tree.proc and path.parent.name.isdigit():
            case.assertNotIn(int(path.parent.name), vectors)
            case.assertNotIn("Threads:", data)
            data += "Threads: 1\n"
        return raw_write(path, data, *args, **kwargs)

    synchronize()
    check()
    threaded = {str(daemon / name) for name in members}
    threaded.update(str(directory) for slot, directory in directories.items() if LEAVES[slot][1] == "threaded")
    threaded.add(str(outer / "thread-root/middle"))
    return write, check, hierarchy, directories, threaded


class TypedDiscoveryTranscriptTests(unittest.TestCase):
    def test_one_task_daemon_fully_typed_production_transcript(self):
        self._run_transcript(daemon_tasks=1)

    def test_three_task_daemon_fully_typed_production_transcript(self):
        self._run_transcript(daemon_tasks=3)

    def _run_transcript(self, *, daemon_tasks):
        outer_test = self

        class Runner(existing.RootFactoryTests):
            def run_factory(self, operation, *, rootful=False):
                outer_test.assertFalse(rootful)

                def adapted(tree, session, channel, request, calls):
                    model_write, check_model, hierarchy, directories, threaded = _typed_kernel_model(tree, self, daemon_tasks)
                    source = tree.source
                    self.assertIs(type(source), locator.LocatorSource)
                    initial_unowned = source.budget.fds - len(source.owned)
                    failed_opens, discoveries, baseline_reads, samples = [], [], [], {}
                    source_closes, seal_releases, removed_leaves = [], [], []
                    expected_counts = {slot: 1 for slot in locator.ORDER}
                    expected_events = {slot: 0 for slot in locator.ORDER}
                    deadline = (source.budget.deadline_ns, source.budget.work_ns)
                    self.assertEqual(deadline, (180_000_000_001, 134_000_000_001))
                    original_open, original_close, original_release = source.open, source.close, source.release_since
                    original_read_type, original_discover = source.read_type, discovery.discover
                    original_response = supervisor.Channel.response

                    def magic(fd, observer=None):
                        path = os.readlink("/proc/self/fd/" + str(fd))
                        return boundary.CGROUP_MAGIC if path.startswith(str(hierarchy)) else boundary.PROC_MAGIC

                    def checked_open(name, parent=None, **options):
                        parent_path = os.readlink("/proc/self/fd/" + str(parent)) if parent is not None else "/"
                        requested = Path(os.path.normpath(os.path.join(parent_path, str(name))))
                        if requested.name == "cgroup.procs":
                            require(str(requested.parent) not in threaded)
                        if daemon_tasks == 3 and requested.is_relative_to(tree.proc):
                            parts = requested.relative_to(tree.proc).parts
                            forbidden = {"111", "112"}
                            # self/fdinfo/<fd> numbers are not process selectors.
                            require(not parts or parts[0] not in forbidden)
                            if parts[:2] == ("110", "task") and len(parts) > 2:
                                require(parts[2] not in forbidden)
                        require(not any(requested == leaf or leaf in requested.parents for leaf in removed_leaves))
                        try:
                            return original_open(name, parent, **options)
                        except OSError:
                            failed_opens.append(True)
                            raise

                    # Verify the observing guard refuses prohibited selectors before I/O.
                    guard_before = (source.budget.reads, source.budget.bytes, source.budget.opens, source.budget.fds)
                    for directory in threaded:
                        with self.assertRaises(boundary.Refusal):
                            checked_open(directory + "/cgroup.procs")
                    if daemon_tasks == 3:
                        for name, parent in (("111/status", source.proc), ("112", source.proc),
                                             ("110/task/111/status", source.proc),
                                             (str(tree.proc / "110/task/112/status"), None)):
                            with self.assertRaises(boundary.Refusal):
                                checked_open(name, parent)
                    self.assertEqual((source.budget.reads, source.budget.bytes, source.budget.opens, source.budget.fds), guard_before)

                    def charged_mount_id(fd):
                        directory = tree.proc / "self/fdinfo"
                        directory.mkdir(exist_ok=True)
                        (directory / str(fd)).write_text("pos:\t0\nflags:\t0100000\nmnt_id:\t10\n")
                        return boundary.LinuxSource.fd_mount_id(source, fd)

                    def read_type(directory):
                        phase = source.type_scope().phase
                        before = (source.budget.reads, source.budget.bytes, source.budget.opens, source.budget.fds)
                        kind = original_read_type(directory)
                        after = (source.budget.reads, source.budget.bytes, source.budget.opens, source.budget.fds)
                        if phase == "locating":
                            baseline_reads.append((os.readlink("/proc/self/fd/" + str(directory)),
                                                   tuple(new - old for old, new in zip(before, after))))
                        return kind

                    def discover(actual_source, outer, mode, consume):
                        self.assertIs(actual_source, source)
                        self.assertIs(type(actual_source), locator.LocatorSource)
                        discoveries.append(mode)
                        def observed(lease):
                            self.assertIs(type(lease), discovery._Lease)
                            self.assertEqual({record.pid for record in lease.candidates}, {100, 110, 200, 201, 202, 203, 204, 205})
                            return consume(lease)
                        transfer = original_discover(actual_source, outer, mode, observed)
                        self.assertEqual(len(transfer.types), 13 if daemon_tasks == 1 else 14)
                        self.assertEqual(len(transfer.selections), 1 if mode is discovery.Mode.PEER else 6)
                        return transfer

                    def release_since(previous):
                        runtime = session.runtime
                        if runtime is not None and previous == runtime.retained:
                            self.assertEqual(source.type_scope().phase, "sealed")
                            self.assertEqual(len(runtime.bound), 6)
                            self.assertEqual(seal_releases, [])
                            seal_releases.append(True)
                        return original_release(previous)

                    def close():
                        original_close()
                        source_closes.append(True)

                    def response(actual_channel, value):
                        runtime = session.runtime
                        if runtime is not None:
                            self.assertIs(type(runtime), locator.RuntimeLocator)
                            self.assertEqual(runtime.outer.membership, ("above", "owned", "init.scope"))
                            self.assertEqual(runtime.outer_group.membership, ("above", "owned"))
                        if value.get("op") == "LocateBatch":
                            self.assertIs(type(source.type_scope()), discovery.topology.TypeScope)
                            self.assertEqual(source.type_scope().phase, "measuring")
                            self.assertEqual(len(source.type_scope().frozen), 11)
                            self.assertEqual(baseline_reads, [(str(tree.cg), (2, 59, 1, 0))])
                        payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
                        self.assertLessEqual(len(payload), 16384)
                        if value.get("op") == "Sample":
                            check_model()
                            slot = locator.ORDER[(value["sequence"] - 4) // 4]
                            phase_index = (value["sequence"] - 4) % 4
                            expected_counts[slot] = 1 if phase_index in (0, 3) else (16 if slot.endswith("16") else 33)
                            if slot.endswith("16") and phase_index == 2:
                                expected_events[slot] = 1
                            sample = value["sample"]
                            self.assertEqual(sample["current"], expected_counts[slot])
                            self.assertEqual(sample["maximum"], "max" if slot.endswith("unlimited") else (16 if slot.endswith("16") else 64))
                            self.assertEqual(sample["events_max"], expected_events[slot])
                            slot_index = locator.ORDER.index(slot)
                            expected_tids = [200 + slot_index] + [1000 + slot_index * 100 + index
                                for index in range(1, expected_counts[slot])]
                            self.assertEqual(sample["tasks"], [[pid, pid * 10] for pid in expected_tids])
                            self.assertEqual(set(sample), {"maximum", "current", "events_max", "cgroup_type",
                                "tasks", "task_namespace_ids", "attribution", "globals"})
                            self.assertEqual(set(sample["attribution"]), {"event_semantics", "pids_localevents",
                                "candidate_membership", "complete_chain", "outer_index",
                                "reader_cgroup_namespace", "hierarchy_root", "controllers"})
                            self.assertEqual(sample["cgroup_type"], LEAVES[slot][1])
                            self.assertEqual(sample["attribution"]["candidate_membership"], "typed_procs_local_membership_v1")
                            rows = sample["attribution"]["controllers"]
                            self.assertEqual(tuple(row["cgroup_type"] for row in rows), CHAINS[slot])
                            self.assertEqual(sample["attribution"]["outer_index"], OUTER_INDEX[slot])
                            expected = directories[slot]
                            for row in rows:
                                self.assertEqual(set(row), {"identity", "cgroup_type", "maximum", "current",
                                    "events_max", "events_local_max", "current_samples", "events_samples",
                                    "events_local_samples"})
                                info = os.stat(expected)
                                self.assertEqual(row["identity"], [info.st_dev, info.st_ino, 10])
                                if expected == directories[slot]:
                                    members, overhead = (slot,), 0
                                elif expected == tree.cg / "owned/thread-root":
                                    members, overhead = ("cli64", "rendered64"), 0
                                elif expected == tree.cg / "owned/thread-root/middle":
                                    members, overhead = ("rendered64",), 0
                                elif expected == tree.cg / "owned/domain-branch":
                                    members, overhead = ("cli_unlimited", "rendered_unlimited"), 0
                                else:
                                    self.assertIn(expected, (tree.cg / "owned", tree.cg))
                                    members, overhead = locator.ORDER, 1 + daemon_tasks
                                current = overhead + sum(expected_counts[member] for member in members)
                                events = sum(expected_events[member] for member in members)
                                self.assertEqual(row["current_samples"], [current, current])
                                self.assertEqual(row["events_samples"], [events, events])
                                local = expected_events[slot] if expected == directories[slot] else 0
                                self.assertEqual(row["events_local_samples"], [local, local])
                                self.assertEqual((row["current"], row["events_max"], row["events_local_max"]), (current, events, local))
                                if expected == tree.cg / "owned":
                                    self.assertEqual(row["maximum"], 512)
                                    self.assertGreaterEqual(512 - current, 32)
                                elif expected == tree.cg:
                                    self.assertEqual(row["maximum"], 2048)
                                expected = expected.parent
                            self.assertEqual(expected, hierarchy)
                            samples.setdefault(slot, []).append(sample)
                        if value.get("op") == "SealMeasurements":
                            self.assertEqual(source.type_scope().phase, "sealed")
                            self.assertEqual(sum(len(values) for values in samples.values()), 24)
                            self.assertTrue(source.budget.cleanup_only)
                            # Actual leaf removal after descriptor retirement. Finalization
                            # must use only surviving retained outer/daemon objects.
                            for directory in directories.values():
                                for leaf_file in directory.iterdir():
                                    leaf_file.unlink()
                                directory.rmdir()
                                removed_leaves.append(directory)
                        if value.get("op") != "OuterFinalize":
                            return original_response(actual_channel, value)
                        self.assertEqual(discoveries, [discovery.Mode.PEER, discovery.Mode.WORKERS])
                        self.assertEqual({slot: len(values) for slot, values in samples.items()}, {slot: 4 for slot in locator.ORDER})
                        self.assertEqual(seal_releases, [True])
                        self.assertEqual(baseline_reads, [(str(tree.cg), (2, 59, 1, 0))])
                        self.assertEqual(source_closes, [True])
                        self.assertEqual(source.type_scope().phase, "sealed")
                        self.assertEqual((source.budget.deadline_ns, source.budget.work_ns), deadline)
                        self.assertTrue(source.budget.cleanup_only)
                        self.assertEqual(len(removed_leaves), 6)
                        self.assertTrue(all(not directory.exists() for directory in removed_leaves))
                        self.assertTrue((tree.cg / "owned/init.scope").is_dir())
                        self.assertTrue((tree.cg / "owned/daemon.scope/member").is_dir())
                        self.assertEqual(source.owned, set())
                        self.assertEqual(source.process_times, {})
                        self.assertTrue(runtime.sealed)
                        self.assertEqual(runtime.bound, {})
                        self.assertEqual(value["reservations"], {"inspect_calls_reserved": 24,
                            "inspect_body_bytes_reserved": 786432, "runtime_probe_calls_reserved": 1,
                            "runtime_probe_body_bytes_reserved": 4096})
                        ledger = value["source_ledger"]
                        self.assertEqual(ledger, source.budget.ledger(0))
                        self.assertEqual(source.budget.frames, 55)
                        self.assertEqual(value["reservations"]["inspect_calls_reserved"]
                            + value["reservations"]["runtime_probe_calls_reserved"], 25)
                        self.assertLessEqual(value["reservations"]["inspect_calls_reserved"]
                            + value["reservations"]["runtime_probe_calls_reserved"], 300)
                        self.assertLessEqual(value["reservations"]["inspect_body_bytes_reserved"]
                            + value["reservations"]["runtime_probe_body_bytes_reserved"], 2097152)
                        self.assertLessEqual(source.budget.bytes, 33554432)
                        self.assertLessEqual(source.budget.reads, 65536)
                        self.assertLessEqual(source.budget.opens, 32768)
                        self.assertLessEqual(source.budget.peak_fds, 256)
                        self.assertEqual(source.budget.fds, initial_unowned + 3 + len(failed_opens))
                        self.assertEqual(initial_unowned, locator.FIXED_FD_RESERVE)
                        # Independent identity/type/parent relation over all 24 source samples.
                        relation, leaves, roots, outers, readers = {}, set(), set(), set(), set()
                        for slot in locator.ORDER:
                            expected_rows = None
                            for sample in samples[slot]:
                                attribution = sample["attribution"]
                                rows = attribution["controllers"]
                                stable_rows = [(tuple(row["identity"]), row["cgroup_type"], row["maximum"]) for row in rows]
                                if expected_rows is None:
                                    expected_rows = stable_rows
                                self.assertEqual(stable_rows, expected_rows)
                                root = tuple(attribution["hierarchy_root"]["identity"])
                                roots.add(root)
                                readers.add(tuple(attribution["reader_cgroup_namespace"]))
                                outers.add(tuple(rows[attribution["outer_index"]]["identity"]))
                                for index, row in enumerate(rows):
                                    key = tuple(row["identity"])
                                    parent = tuple(rows[index + 1]["identity"]) if index + 1 < len(rows) else root
                                    observed = (row["cgroup_type"], parent)
                                    self.assertEqual(relation.setdefault(key, observed), observed)
                            leaves.add(expected_rows[0][0])
                        self.assertEqual((len(relation), len(leaves), len(roots), len(outers), len(readers)), (11, 6, 1, 1, 1))
                        original_response(actual_channel, value)
                        frame = len(json.dumps(value, separators=(",", ":"), sort_keys=True).encode()) + 4
                        self.assertEqual(source.budget.output, ledger["output_reserved_before_final"] + frame)
                        self.assertLessEqual(source.budget.output, 65536)
                        print("typed_discovery_transcript_metrics=" + json.dumps({
                            "scenario": f"{daemon_tasks}_task_daemon", "daemon_tasks": daemon_tasks,
                            "discoveries": 2, "samples": 24, "owner_requests": 30,
                            "api_acknowledgments": 25, "api_reserved_bytes": 790528,
                            "baseline_type_reads": len(baseline_reads), "baseline_source_read_reservations": 2,
                            "baseline_type_reserved_bytes": 59,
                            "source_reserved_bytes": source.budget.bytes, "source_read_reservations": source.budget.reads,
                            "fd_open_reservations": source.budget.opens, "fd_peak_reservations": source.budget.peak_fds,
                            "remaining_fd_reservations": source.budget.fds, "failed_open_reservations": len(failed_opens),
                            "output_bytes": source.budget.output, "input_frames": source.budget.frames,
                            "owned_remaining": len(source.owned)}, sort_keys=True), flush=True)

                    def checked_response(actual_channel, value):
                        try:
                            return response(actual_channel, value)
                        except BaseException:
                            import traceback
                            traceback.print_exc()
                            raise

                    with patch.object(Path, "write_text", model_write), \
                            patch.object(boundary, "fs_magic", side_effect=magic), \
                            patch.object(source, "open", checked_open), \
                            patch.object(source, "fd_mount_id", charged_mount_id), \
                            patch.object(source, "read_type", read_type), \
                            patch.object(discovery, "discover", discover), \
                            patch.object(source, "release_since", release_since), \
                            patch.object(source, "close", close), \
                            patch.object(supervisor.Channel, "response", checked_response):
                        return operation(tree, session, channel, request, calls)

                return super().run_factory(adapted, rootful=rootful)

        # Reuse the actual socketpair/fork/server/30-request/25-ack loop verbatim.
        Runner().test_full_factory_transcript_actual_ipc_has_30_owner_requests_and_25_debit_acks()


if __name__ == "__main__":
    unittest.main()
