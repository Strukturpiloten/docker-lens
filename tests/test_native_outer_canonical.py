"""Fake-process canonical activation controls; never sudo, Podman or containers."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import native_outer_canonical as canonical
from native_outer_coordinator import CoordinationError, PHASE_BYTES, phase_read, phase_write
import test_native_outer_coordinator as context_fixtures

ROOT = Path(__file__).resolve().parents[1]


class CanonicalTests(unittest.TestCase):
    def private_context(self):
        value = context_fixtures.ConsumerContextTests().context()
        value["binding"]["execution_origin"] = "github_actions"
        return value

    def coordinator(self):
        value = canonical.Canonical("2" * 40, "upstream-rootful", time.monotonic_ns() + 600_000_000_000)
        value.intent = SimpleNamespace(run_directory="/tmp/dockerlens-native.AbCd1234", owner="AbCd1234",
                                       image_ref="owned-image", name="dl-native-AbCd1234",
                                       socket_source="/tmp/dockerlens-native.AbCd1234/socket")
        value.endpoint = SimpleNamespace(id="3" * 64)
        value.caller = SimpleNamespace(recheck=lambda: None)
        value.state = "started"
        value.version_record = lambda: ("29.8.1", "1.49")
        return value

    def metadata(self):
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        fixture = canonical.re.search(r"^FIXTURE_IMAGE='([^']+)'$", source, canonical.re.M)[1]
        return ["/tmp/dockerlens-native.AbCd1234", "2" * 40, "AbCd1234", "upstream-rootful", "29.8.1", "1.49",
                "rootful", "", fixture, "owned-image", "3" * 64, "0"]

    def test_closed_metadata_refuses_cross_candidate_outer_lane_and_fixture(self):
        value = self.coordinator()
        self.assertEqual(value.reader_arguments(self.metadata()), self.metadata())
        for index, replacement in ((0, "/tmp/other"), (1, "4" * 40), (2, "Other123"), (3, "upstream-rootless"),
                                   (4, "20.10.5"), (5, "1.41"), (6, "rootless"), (7, "invented"),
                                   (8, "other-image"), (9, "other-image"), (10, "4" * 64), (11, "-1")):
            arguments = self.metadata()
            arguments[index] = replacement
            with self.subTest(index=index), self.assertRaises(CoordinationError):
                value.reader_arguments(arguments)

    def test_all_four_lanes_keep_observed_api_and_debian_source_suffix(self):
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            with self.subTest(lane=lane):
                value, metadata = self.coordinator(), self.metadata()
                value.lane = metadata[3] = lane
                metadata[4] = "20.10.5+dfsg1" if lane.startswith("debian11-") else "29.8.1"
                metadata[5] = "1.41" if lane.startswith("debian11-") else "1.56"
                metadata[6] = "rootless" if lane.endswith("rootless") else "rootful"
                metadata[7] = "20.10.5+dfsg1-1+deb11u2" if lane.startswith("debian11-") else ""
                value.version_record = lambda: (metadata[4], metadata[5])
                self.assertEqual(value.reader_arguments(metadata), metadata)

    def test_producer_reader_seal_final_and_once_only_reservations(self):
        value = self.coordinator()
        events, children = [], []
        value.exchange = lambda verb, payload=None: events.append(verb)
        context = self.private_context()
        def build_context(timing):
            context["pids"].update(start_ns=timing.start_ns, deadline_ns=timing.deadline_ns,
                                    deadline_epoch=value.deadline_epoch)
            return context
        value.make_context = build_context
        def run(argv, env, raw, budget, deadline):
            children.append((argv, env, json.loads(raw), deadline))
            self.assertIs(budget, value.scope)
        with patch.object(canonical, "run_private_role", run), patch.dict(os.environ, {"NATIVE_EVIL": "secret"}):
            value.dispatch(["producer", *self.metadata(), "a" * 64])
            self.assertEqual(events, ["begin_pids", "pids_before_producer", "pids_before_reader"])
            self.assertEqual(value.state, "produced")
            self.assertNotIn("NATIVE_EVIL", children[0][1])
            self.assertNotIn("DOCKERLENS_CANONICAL_PIDS", children[0][1])
            self.assertEqual(children[0][1]["NATIVE_PIDS_LIMIT_DEADLINE_EPOCH"], str(value.deadline_epoch))
            self.assertEqual(children[0][0][-2:], (canonical.PIDS_TARGET, canonical.PIDS_TEST))
            self.assertIn(value.roles["producer"].sequence, value.book._claimed)
            with self.assertRaises(CoordinationError):
                value.dispatch(["producer", *self.metadata(), "a" * 64])
            value.dispatch(["reader", *self.metadata()])
            self.assertEqual(events[-1], "seal_pids")
            self.assertEqual(value.state, "sealed")
            self.assertEqual(children[0][2], children[1][2])
            self.assertEqual(children[0][3], children[1][3])
            self.assertEqual(value.scope.active, value.scope.lane)
            value.dispatch(["final"])
            self.assertEqual(value.state, "final")
            with self.assertRaises(CoordinationError):
                value.dispatch(["reader", *self.metadata()])

    def test_failed_producer_retains_original_scope_and_cannot_refund_role(self):
        value = self.coordinator()
        value.exchange = lambda *_arguments: None
        value.make_context = lambda _timing: self.private_context()
        with patch.object(canonical, "run_private_role", side_effect=CoordinationError()):
            with self.assertRaises(CoordinationError):
                value.producer([*self.metadata(), "a" * 64])
        self.assertTrue(value.scope.started)
        self.assertFalse(value.scope.ended)
        with self.assertRaises(CoordinationError):
            value.book.claim_before_spawn(value.roles["producer"])
        with self.assertRaises(CoordinationError):
            value.reader(self.metadata())

    def test_optional_emitter_has_original_lane_budget_and_fixed_nineteen_argument_stdin_dispatch(self):
        value = self.coordinator()
        value.context = self.private_context()
        value.metadata = self.metadata()
        value.state = "sealed"
        events, children = [], []
        value.exchange = lambda verb, _payload=None: events.append(verb)
        directory = value.intent.run_directory
        names = ("version.json", "target-shapes.json", "source-probes.json", "network-probes.json", "volume-probes.json",
                 "volume-label-probes.json", "identity-probes.json", "port-probes.json", "health-metadata.json",
                 "network-attachments-v1.json", "bind-relabel-config-v1.json")
        arguments = [*(directory + "/" + name for name in names), directory, "/private/evidence/upstream-rootful.json",
                     value.lane, value.intent.image_ref, "rootful", "", value.candidate, value.intent.owner]
        def run(argv, env, raw, budget, deadline):
            children.append((argv, env, raw, budget, deadline))
        with patch.object(canonical, "run_private_role", side_effect=run), \
             patch.dict(os.environ, DOCKERLENS_NATIVE_EVIDENCE_DIR="/private/evidence", NATIVE_EVIL="secret",
                        NATIVE_FIXTURE_IMAGE="untrusted-fixture", NATIVE_OUTER_CONTAINER_ID="untrusted-outer",
                        NATIVE_BIND_RELABEL_DAEMON_UID="untrusted-uid"):
            value.emitter(arguments)
        self.assertEqual(events, ["recheck"])
        self.assertEqual(children[0][0][4:], tuple(arguments))
        self.assertEqual(len(children[0][0][4:]), 19)
        self.assertEqual(json.loads(children[0][2]), value.context)
        self.assertEqual(children[0][1]["DOCKERLENS_OUTER_LANE_DEADLINE_NS"], str(value.deadline_ns))
        self.assertEqual({name: children[0][1][name] for name in
                          ("NATIVE_FIXTURE_IMAGE", "NATIVE_OUTER_CONTAINER_ID", "NATIVE_BIND_RELABEL_DAEMON_UID")},
                         {"NATIVE_FIXTURE_IMAGE": value.metadata[8], "NATIVE_OUTER_CONTAINER_ID": value.metadata[10],
                          "NATIVE_BIND_RELABEL_DAEMON_UID": value.metadata[11]})
        self.assertNotIn("NATIVE_EVIL", children[0][1])
        self.assertIs(children[0][3], value.scope)
        self.assertIs(value.scope.active, value.scope.lane)
        self.assertIn(value.roles["emitter"].sequence, value.book._claimed)
        with self.assertRaises(CoordinationError):
            value.emitter(arguments)

    def test_setup_claims_root_roles_before_spawn_and_validates_original_oci_before_start(self):
        for invalid_oci in (False, True):
            with self.subTest(invalid_oci=invalid_oci):
                value = self.coordinator()
                value.state = "new"
                events = []
                account = SimpleNamespace(image_digest="sha256:" + "a" * 64)
                profile = canonical.RuntimeProfile("linux", False, False, "4.9.3", "crun", "1.14.1", "systemd", "v2")
                receipts = {"preflight": SimpleNamespace(runtime_profile=vars(profile)),
                            "initialize": SimpleNamespace(init_pid=123),
                            "bind_expectation": SimpleNamespace(raw=b"original OCI")}
                def exchange(verb, _payload=None):
                    events.append(verb)
                    return receipts.get(verb)
                value.exchange = exchange
                pipe_read, pipe_write = os.pipe()
                caller = SimpleNamespace(_log=SimpleNamespace(fd=pipe_read),
                                         empty=lambda: events.append("empty"), capture=lambda: events.append("capture"))
                def custody(*_args):
                    events.append("caller_log_birth")
                    return caller
                def diagnostic_adopt(*_args, **keywords):
                    self.assertEqual(set(keywords), {"budget"})
                    self.assertIs(keywords["budget"], value.scope)
                    events.append("diagnostic_adopt")
                def spawn(argv, **options):
                    for role in ("root_lane", "root_pids", "root_recovery"):
                        self.assertIn(value.roles[role].sequence, value.book._claimed)
                    self.assertEqual(argv[:5], ("/usr/bin/sudo", "-n", "/usr/bin/python3", "-E", "-s"))
                    self.assertTrue(options["close_fds"])
                    self.assertNotIn("pass_fds", options)
                    self.assertEqual(len(argv[6:]), 14)
                    self.assertEqual(argv[8], value.execution_origin)
                    if value.execution_origin == "local_process":
                        self.assertEqual(argv[9:11], ("", ""))
                    return SimpleNamespace(stdout=SimpleNamespace(fileno=lambda: 10), stdin=SimpleNamespace(fileno=lambda: 11))
                value.spawn = spawn
                def endpoint(_role, binding, *_args, **_kwargs):
                    return SimpleNamespace(id="3" * 64, binding=binding)
                def validate(raw, _expected, identifier):
                    events.append("independent_oci_validation")
                    self.assertEqual((raw, identifier), (b"original OCI", "3" * 64))
                    if invalid_oci:
                        raise CoordinationError()
                try:
                    with patch.object(canonical, "candidate_account", return_value=account), \
                         patch.object(canonical, "image_observation", return_value=SimpleNamespace(launch_image=lambda: {})), \
                         patch.object(canonical, "socket_mount_options", return_value=("rw", "rprivate", "rbind")), \
                         patch.object(canonical, "intent_digest", return_value="4" * 64), \
                         patch.object(canonical, "expectation_digest", return_value="5" * 64), \
                         patch.object(canonical, "derive_launch", return_value=SimpleNamespace()), \
                         patch.object(canonical, "source_defaults", return_value=SimpleNamespace()), \
                         patch.object(canonical, "CallerLogCustody", side_effect=custody), \
                         patch.object(canonical, "Endpoint", side_effect=endpoint), \
                         patch.object(canonical, "diagnostic_prepare", side_effect=diagnostic_adopt), \
                         patch.object(canonical, "_validate_oci", side_effect=validate), \
                         patch.object(canonical.os, "geteuid", return_value=1000), \
                         patch.object(canonical.os, "pread", return_value=b"timestamp stdout F frame\n"), \
                         patch.dict(os.environ, GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="1"):
                        arguments = ["/tmp/dockerlens-native.AbCd1234", "AbCd1234", "upstream-rootful", "owned-image"]
                        if invalid_oci:
                            with self.assertRaises(CoordinationError):
                                value.setup(arguments)
                            self.assertNotIn("start", events)
                        else:
                            value.setup(arguments)
                            self.assertEqual(events, ["preflight", "caller_log_birth", "diagnostic_adopt", "empty", "create",
                                                      "initialize", "bind_expectation", "independent_oci_validation", "start", "capture"])
                finally:
                    os.close(pipe_read)
                    os.close(pipe_write)

    def test_version_record_uses_observed_rendering_api_and_rejects_links_duplicates_and_overflow(self):
        value = self.coordinator()
        with tempfile.TemporaryDirectory() as directory:
            value.intent.run_directory = directory
            record = Path(directory) / "version.json"
            # Exercise actual bounded owned-file reads, no daemon query.
            del value.version_record
            record.write_text('{"Version":"29.8.1","ApiVersion":"1.56"}')
            self.assertEqual(value.version_record(), ("29.8.1", "1.56"))
            for raw in ('{"Version":"29.8.1","Version":"29.8.1","ApiVersion":"1.56"}', "x" * 16385):
                record.write_text(raw)
                with self.assertRaises(CoordinationError):
                    value.version_record()
            record.unlink()
            record.symlink_to(Path(directory) / "missing")
            with self.assertRaises(OSError):
                value.version_record()

    def test_close_errors_cannot_skip_other_pipe_root_wait_or_log_finalization(self):
        for wait_error in (False, True):
            with self.subTest(wait_error=wait_error):
                value, events = self.coordinator(), []
                def close_endpoint():
                    events.append("endpoint")
                    raise CoordinationError()
                def close_input():
                    events.append("stdin")
                    raise RuntimeError("synthetic close failure")
                def wait(*_args, **_kwargs):
                    events.append("root_wait")
                    if wait_error:
                        raise subprocess.TimeoutExpired("fake-root", 1)
                    return 0
                value.endpoint = SimpleNamespace(close=close_endpoint)
                value.broker = SimpleNamespace(stdin=SimpleNamespace(close=close_input),
                                               stdout=SimpleNamespace(close=lambda: events.append("stdout")), wait=wait)
                value.caller = SimpleNamespace(close=lambda: events.append("log"))
                with self.assertRaises(CoordinationError):
                    value.close()
                self.assertEqual(events, ["endpoint", "stdin", "stdout", "root_wait", "log"])

    def test_actual_shell_relay_proxy_survives_external_commands_and_closes_upstream(self):
        # Exercise the actual bootstrap prefix before its first external command.
        prefix = (ROOT / "scripts/native-conformance.sh").read_text().split("script_dir=$(", 1)[0]
        request_read, request_write = os.pipe()
        reply_read, reply_write = os.pipe()
        env = dict(os.environ, DOCKERLENS_CANONICAL_ACTIVE="1", DOCKERLENS_CANONICAL_REQUEST_FD=str(request_write),
                   DOCKERLENS_CANONICAL_REPLY_FD=str(reply_read))
        program = prefix.replace('"${BASH_SOURCE[0]%/*}/native_outer_canonical.py"',
                                 '"' + str(ROOT / "scripts/native_outer_canonical.py") + '"')
        program += '\nscript_dir="' + str(ROOT / "scripts") + '"\n'
        program += '/usr/bin/python3 -c "import os; assert len(os.listdir(\'/proc/self/fd\')) == 4"\n'
        program += 'canonical_phase setup one two three four\ncanonical_phase final\n'
        process = subprocess.Popen(("/bin/bash", "-c", program), env=env, pass_fds=(request_write, reply_read),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        os.close(request_write)
        os.close(reply_read)
        try:
            for expected in (["setup", "one", "two", "three", "four"], ["final"]):
                self.assertEqual(phase_read(request_read, deadline_ns=time.monotonic_ns() + 3_000_000_000), expected)
                phase_write(reply_write, {"ok": True})
            output, error = process.communicate(timeout=3)
            self.assertEqual(process.returncode, 0, error)
            self.assertEqual(output, b"")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            os.close(request_read)
            os.close(reply_write)

    def test_launcher_eof_malformed_and_late_ack_kill_entire_shell_group(self):
        prefix = (ROOT / "scripts/native-conformance.sh").read_text().split("script_dir=$(", 1)[0]
        prefix = prefix.replace('"${BASH_SOURCE[0]%/*}/native_outer_canonical.py"',
                                '"' + str(ROOT / "scripts/native_outer_canonical.py") + '"')
        for failure in ("eof", "malformed", "late_ack"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                child_pid = Path(directory) / "child.pid"
                shell = Path(directory) / "fake-lane.sh"
                program = prefix + '\nscript_dir="' + str(ROOT / "scripts") + '"\n'
                program += '/bin/sleep 30 &\nprintf "%s" "$!" > "' + str(child_pid) + '"\n'
                if failure == "eof":
                    program += "exit 1\n"
                elif failure == "malformed":
                    # Zero-length frame sent through the relay's existing stdin.
                    program += "printf '\\000\\000\\000\\000' >&\"$canonical_write\"\nwait \"$CANONICAL_RELAY_PID\"\n"
                else:
                    program += "canonical_phase final\n"
                shell.write_text(program)
                closed, dispatched = [], []
                fake = SimpleNamespace(deadline_ns=time.monotonic_ns() + 600_000_000,
                                       cancelled=False, state="new", final_verified=False,
                                       close=lambda: closed.append(True), scope=self.coordinator().scope, phase_stats={})
                def dispatch(request):
                    dispatched.append(request)
                    if failure == "late_ack":
                        time.sleep(max(0, (fake.deadline_ns - time.monotonic_ns()) / 1e9) + 0.02)
                fake.dispatch = dispatch
                fake.ack_deadline = lambda _phase: fake.deadline_ns
                spawned = []
                actual_spawn = subprocess.Popen
                def spawn(*args, **kwargs):
                    process = actual_spawn(*args, **kwargs)
                    spawned.append(process)
                    return process
                with patch.object(canonical, "Canonical", return_value=fake), \
                     patch.object(canonical.subprocess, "run", return_value=SimpleNamespace(stdout=b"2" * 40 + b"\n")), \
                     patch.object(canonical.subprocess, "Popen", side_effect=spawn), \
                     patch.dict(os.environ, DOCKERLENS_CANONICAL_ACTIVE="1"):
                    with self.assertRaises(CoordinationError):
                        canonical.launch(str(shell), "upstream-rootful")
                # For deliberately expired D, production makes only a
                # nonblocking reap attempt. Reap this fake after observing the
                # failure; this grants no production cleanup time or success.
                for process in spawned:
                    process.wait(timeout=1)
                self.assertEqual(closed, [True])
                self.assertEqual(dispatched, [["final"]] if failure == "late_ack" else [])
                pid = int(child_pid.read_text())
                status = Path("/proc") / str(pid) / "stat"
                # A reparented zombie is terminated; a sleeping descendant is
                # an escaped process-group cancellation and fails this control.
                delivery_deadline = time.monotonic() + 0.5
                while status.exists() and status.read_text().split()[2] != "Z" and time.monotonic() < delivery_deadline:
                    time.sleep(0.01)
                if status.exists():
                    self.assertEqual(status.read_text().split()[2], "Z")

    def test_missing_bootstrap_pipe_is_fatal_before_external_setup(self):
        prefix = (ROOT / "scripts/native-conformance.sh").read_text().split("script_dir=$(", 1)[0]
        prefix = prefix.replace('"${BASH_SOURCE[0]%/*}/native_outer_canonical.py"',
                                '"' + str(ROOT / "scripts/native_outer_canonical.py") + '"')
        program = prefix + '\nscript_dir="' + str(ROOT / "scripts") + '"\ncanonical_phase final\n'
        env = dict(os.environ, DOCKERLENS_CANONICAL_ACTIVE="1", DOCKERLENS_CANONICAL_REQUEST_FD="998",
                   DOCKERLENS_CANONICAL_REPLY_FD="999")
        result = subprocess.run(("/bin/bash", "-c", program), env=env, capture_output=True, timeout=3, close_fds=True)
        self.assertNotEqual(result.returncode, 0)

    def test_production_server_control_budget_exhaustion_prevents_second_dispatch(self):
        value = self.coordinator()
        value.state = "new"
        dispatched, closed = [], []
        value.dispatch = lambda request: dispatched.append(request)
        value.close = lambda: closed.append(True)
        request_credit = 2 * (PHASE_BYTES + 4)
        ack = json.dumps({"ok": True}, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
        ack_credit = 2 * (4 + len(ack))
        budget = value.scope.lane
        cap = budget.reservation.allowance.source_bytes
        # Leave one successful request/reply and a single byte in the ORIGINAL
        # caller reservation. There is no new role, pool, refund or reset.
        budget.debit(source_bytes=cap - budget.used.source_bytes - request_credit - ack_credit - 1)
        before = budget.used.source_bytes
        prefix = (ROOT / "scripts/native-conformance.sh").read_text().split("script_dir=$(", 1)[0]
        prefix = prefix.replace('"${BASH_SOURCE[0]%/*}/native_outer_canonical.py"',
                                '"' + str(ROOT / "scripts/native_outer_canonical.py") + '"')
        with tempfile.TemporaryDirectory() as directory:
            shell = Path(directory) / "fake-budget-lane.sh"
            shell.write_text(prefix + '\nscript_dir="' + str(ROOT / "scripts") +
                             '"\ncanonical_phase final\ncanonical_phase final\n')
            with patch.object(canonical, "Canonical", return_value=value), \
                 patch.object(canonical.subprocess, "run", return_value=SimpleNamespace(stdout=b"2" * 40 + b"\n")), \
                 patch.dict(os.environ, DOCKERLENS_CANONICAL_ACTIVE="1"):
                with self.assertRaises(CoordinationError):
                    canonical.launch(str(shell), "upstream-rootful")
        self.assertEqual(dispatched, [["final"]])
        self.assertEqual(closed, [True])
        self.assertEqual(budget.used.source_bytes - before, request_credit + ack_credit)
        self.assertEqual(cap - budget.used.source_bytes, 1)
        self.assertTrue(budget.poisoned)
        self.assertEqual(value.phase_stats, {"read": 4 + len(b'["final"]'), "written": 4 + len(ack)})
        self.assertEqual(budget.used.native_calls, 0)

    def test_production_server_partial_eof_and_malformed_frames_prepay_without_dispatch_or_refund(self):
        cases = (("\\000\\000", 2), ("\\000\\000\\000\\010[", 5),
                 ("\\000\\000\\000\\000", 4), ("\\000\\000\\040\\001", 4))
        for frame, observed_bytes in cases:
            with self.subTest(frame=frame), tempfile.TemporaryDirectory() as directory:
                value = self.coordinator()
                value.state = "new"
                dispatched, closed = [], []
                value.dispatch = lambda request: dispatched.append(request)
                value.close = lambda: closed.append(True)
                before = value.scope.lane.used.source_bytes
                shell = Path(directory) / "fake-partial-lane.sh"
                # Directly model a failed relay's upstream pipe: no completed
                # frame reaches the coordinator, and EOF arrives while this
                # short-lived fake shell is still alive.
                shell.write_text('''#!/bin/bash
set -euo pipefail
printf 'zFRAME' >&"$DOCKERLENS_CANONICAL_REQUEST_FD"
exec {DOCKERLENS_CANONICAL_REQUEST_FD}>&-
/bin/sleep 0.1
'''.replace("zFRAME", frame))
                with patch.object(canonical, "Canonical", return_value=value), \
                     patch.object(canonical.subprocess, "run", return_value=SimpleNamespace(stdout=b"2" * 40 + b"\n")):
                    with self.assertRaises(CoordinationError):
                        canonical.launch(str(shell), "upstream-rootful")
                self.assertEqual(dispatched, [])
                self.assertEqual(closed, [True])
                self.assertEqual(value.scope.lane.used.source_bytes - before, 2 * (PHASE_BYTES + 4))
                self.assertEqual(value.phase_stats, {"read": observed_bytes})
                self.assertEqual(value.scope.lane.used.native_calls, 0)

    def test_local_and_hosted_provenance_are_typed_and_partial_hosted_identity_fails_before_spawn(self):
        self.assertEqual(canonical.execution_identity({}), ("local_process", None, None))
        self.assertEqual(canonical.execution_identity({"GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2"}),
                         ("github_actions", "123", "2"))
        for environment in ({"GITHUB_ACTIONS": "true"}, {"GITHUB_RUN_ID": "123"}, {"GITHUB_RUN_ATTEMPT": "1"},
                            {"GITHUB_RUN_ID": "01", "GITHUB_RUN_ATTEMPT": "1"},
                            {"GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": ""},
                            {"GITHUB_ACTIONS": "false", "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"}):
            with self.subTest(environment=environment), patch.dict(os.environ, environment, clear=True), \
                 patch.object(canonical, "Canonical") as coordinator, \
                 patch.object(canonical.subprocess, "run") as run, patch.object(canonical.subprocess, "Popen") as spawn:
                with self.assertRaises(CoordinationError):
                    canonical.launch("never-executed", "upstream-rootful")
                coordinator.assert_not_called()
                run.assert_not_called()
                spawn.assert_not_called()

    def test_lost_ack_cleanup_waits_root_then_independently_checks_absence_before_other_resources(self):
        source = (ROOT / "scripts/native-conformance.sh").read_text()
        prefix = source.split("script_dir=$(", 1)[0].replace('"${BASH_SOURCE[0]%/*}/native_outer_canonical.py"',
                  '"' + str(ROOT / "scripts/native_outer_canonical.py") + '"')
        cleanup = "cleanup() {" + source.split("cleanup() {", 1)[1].split("cleanup_container() {", 1)[0]
        for root_close_error in (False, True):
            with self.subTest(root_close_error=root_close_error), tempfile.TemporaryDirectory() as directory:
                trace, root_done = Path(directory) / "trace", Path(directory) / "root-done"
                shell = Path(directory) / "fake-lane.sh"
                program = prefix + '\nscript_dir="' + str(ROOT / "scripts") + '"\n' + cleanup
                program += '\ntrace="' + str(trace) + '"; root_done="' + str(root_done) + '"\n'
                program += '''
watchdog_pid=; preserve_run_dir=1; run_dir=/private/not-removed; lane=upstream-rootful
container=dl-native-AbCd1234; sidecar=dl-native-egress-AbCd1234
outer_network=dl-native-net-AbCd1234; volume=dl-native-data-AbCd1234
outer_attempted=1; outer_container_id=''' + "3" * 64 + '''
sidecar_container_id=''' + "4" * 64 + '''; sidecar_attempted=1; podman_cmd=(never-executed)
native_presence() { [[ -f $root_done ]] || exit 91; printf 'absent:%s\n' "${@: -1}" >> "$trace"; return 1; }
cleanup_container() { printf 'sidecar\n' >> "$trace"; }
cleanup_network() { printf 'network\n' >> "$trace"; }
cleanup_volume() { printf 'volume\n' >> "$trace"; }
cleanup_refuse() { printf 'refused:%s\n' "$1" >> "$trace"; status=1; }
trap cleanup EXIT
trap 'exit 143' TERM
canonical_phase final
'''
                shell.write_text(program)
                fake = SimpleNamespace(deadline_ns=time.monotonic_ns() + 3_000_000_000, cancelled=False,
                                       state="new", final_verified=False, scope=self.coordinator().scope, phase_stats={})
                def close():
                    root_done.write_text("root-cleanup-finished")
                    if root_close_error:
                        raise CoordinationError()
                fake.close = close
                fake.dispatch = lambda _request: (_ for _ in ()).throw(CoordinationError())
                with patch.object(canonical, "Canonical", return_value=fake), \
                     patch.object(canonical.subprocess, "run", return_value=SimpleNamespace(stdout=b"2" * 40 + b"\n")), \
                     patch.dict(os.environ, DOCKERLENS_CANONICAL_ACTIVE="1"):
                    with self.assertRaises(CoordinationError):
                        canonical.launch(str(shell), "upstream-rootful")
                self.assertEqual(trace.read_text().splitlines(),
                                 ["absent:dl-native-AbCd1234", "absent:" + "3" * 64, "sidecar", "network", "volume"])

    def test_runner_lists_before_proxy_and_actual_child_preserves_stdin_and_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace.json"
            cargo = Path(directory) / "cargo"
            selected = "native_health_metadata_tests::lifecycle::pids_limit::" + canonical.PIDS_TEST
            cargo.write_text("#!" + sys.executable + "\nimport json,os,sys\nfrom pathlib import Path\n"
                             "p=Path(" + repr(str(trace)) + ")\n"
                             "if '--list' in sys.argv:\n assert sys.stdin.read() == ''; p.write_text('listed'); print(" + repr(selected + ": test") + ")\n"
                             "else:\n p.write_text(json.dumps([sys.stdin.read(),os.environ['NATIVE_PIDS_LIMIT_DEADLINE_EPOCH']])); "
                             "print('test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;')\n")
            cargo.chmod(0o700)
            arguments = self.metadata()
            env = dict(os.environ, PATH=directory + ":" + os.environ["PATH"], DOCKERLENS_CANONICAL_PIDS="1")
            names = ("NATIVE_CAPTURE_DIR", "NATIVE_PIDS_LIMIT_CANDIDATE_SHA", "unused", "NATIVE_LANE", "NATIVE_ENGINE_VERSION",
                     "NATIVE_API_VERSION", "NATIVE_DAEMON_MODE", "NATIVE_DOCKER_PACKAGE", "NATIVE_FIXTURE_IMAGE",
                     "NATIVE_OUTER_IMAGE", "NATIVE_OUTER_CONTAINER_ID", "NATIVE_BIND_RELABEL_DAEMON_UID")
            env.update(zip(names, arguments))
            env["NATIVE_CONTAINER_ID"] = "a" * 64
            process = subprocess.Popen(("/bin/bash", str(ROOT / "scripts/run-exact-native-test.sh"), canonical.PIDS_TARGET,
                                        canonical.PIDS_TEST), env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                request = phase_read(process.stdout.fileno(), deadline_ns=time.monotonic_ns() + 3_000_000_000)
                self.assertEqual(trace.read_text(), "listed")
                self.assertEqual(request, ["producer", *arguments, "a" * 64])
                phase_write(process.stdin.fileno(), {"ok": True})
                process.stdin.close()
                self.assertEqual(process.wait(timeout=3), 0, process.stderr.read())
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                process.stdout.close()
                process.stderr.close()
            env.pop("DOCKERLENS_CANONICAL_PIDS")
            original_deadline = str(int(time.time()) + 90)
            env.update(DOCKERLENS_CANONICAL_CHILD="1", NATIVE_PIDS_LIMIT_DEADLINE_EPOCH=original_deadline)
            result = subprocess.run(("/bin/bash", str(ROOT / "scripts/run-exact-native-test.sh"), canonical.PIDS_TARGET,
                                     canonical.PIDS_TEST), env=env, input=b"private-context", capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(trace.read_text()), ["private-context", original_deadline])


if __name__ == "__main__":
    unittest.main()
