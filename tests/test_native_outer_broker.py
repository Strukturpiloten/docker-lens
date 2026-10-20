"""Actual separate fake broker/runtime processes; no container engine commands."""

from dataclasses import replace
from contextlib import ExitStack, nullcontext
import fcntl
import hashlib
import inspect
import json
import os
from pathlib import Path
import secrets
import shlex
import subprocess
import sys
import tempfile
import time
from threading import Thread
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import native_outer_lifecycle as lifecycle_module
import native_outer_coordinator as coordinator

from native_outer_broker import RootBroker
from native_outer_broker_protocol import (Binding, Empty, Endpoint, ExpectationClaim, Ledger, PidsTiming,
                                         PidsWindow, ProtocolError, payload_read)
from native_outer_coordinator import Allowance, Reservation, ReservedBudget
from native_outer_launch import CreateIntent, derive_launch, expectation_digest, source_defaults
from native_outer_lifecycle import LifecycleError, RuntimeProfile
from native_outer_runtime import BoundedNativeProcess
from native_outer_runtime import FixedPodmanRuntime
from test_native_outer_authority import authority_fixture


def broker_worker(mode):
    context, _expected, account, options, _prefix, _proof = authority_fixture()
    intent = CreateIntent(**context["source"]["intent"])
    binding = Binding(context["binding"]["session"], context["binding"]["candidate_sha"], "123", "1",
                      context["binding"]["intent_digest"], account.image_digest)
    now = time.monotonic()
    endpoint = Endpoint("broker", binding, 0, 1, Ledger(10000, 1048576, now + 10, now + 200, now + 210,
                                                      now + 210, time.monotonic, lambda: False),
                        pids_window=PidsWindow(int((now + 200) * 1e9), time.monotonic_ns))
    events = []
    database = payload_read("initialize", context["source"]["database"])
    class Runtime:
        profile = RuntimeProfile("linux", False, False, "4.9.3", "crun", "1.14.1", "systemd", "v2")
        expectation = None
        def __init__(self):
            self.image = SimpleNamespace(launch_image=lambda: {
                "digest": account.image_digest, "platform_digest": account.platform_digest,
                "config_digest": account.config_digest, "architecture": account.architecture,
                "config": context["source"]["preflight"]["semantic"]["config"]})
        def preflight(self, deadline):
            # Separate fake runtime sees neither broker stdin nor an inherited
            # deliberately inheritable high control descriptor.
            budget = ReservedBudget(Reservation(secrets.token_hex(32), 1, "fake_runtime", "test",
                                                 Allowance(1, 100, 1000), time.monotonic_ns() + 5_000_000_000),
                                    time.monotonic_ns, lambda: False)
            code = ("import os,sys;assert sys.stdin.buffer.read()==b''"
                    "\ntry:os.fstat(100)"
                    "\nexcept OSError:os.write(1,b'closed')"
                    "\nelse:raise SystemExit(9)")
            output, _status = BoundedNativeProcess(budget).run((sys.executable, "-c", code), deadline,
                                                               {"PATH": "/usr/bin:/bin"}, seconds=2)
            assert output == b"closed"
            events.append("preflight")
            return payload_read("preflight", context["source"]["preflight"])
        def database_receipt(self, deadline):
            events.append("database")
            return database
        def close(self):
            events.append("runtime_closed")
    class Custody:
        def __init__(self, expected, profile, runtime, log_path, budget, *remaining):
            self.expectation, self._id, self._pid = expected, None, 2345
            self.cleanup_obligation = "none"
            self.bound = self.closed = False
            self.raw = b"x" * (65536 if mode == "large" else 100)
            self.info = SimpleNamespace(device=11, inode=12, uid=0, mode=0o100600, links=1, size=len(self.raw))
        def create(self):
            events.append("create")
            if mode == "unknown_create":
                self.cleanup_obligation = "unknown_create"
                raise LifecycleError()
            self._id, self.cleanup_obligation = context["binding"]["outer_id"], "live_id"
            return self._id
        def initialize(self):
            events.append("held_before_database")
        def bind_expectation(self, expected):
            assert events[-1] == "database"
            self.expectation, self.bound = expected, True
            events.append("bound")
        def original_oci(self):
            assert self.bound
            return self.raw, self.info, self._pid
        def arm(self):
            assert self.bound
        def start(self):
            events.append("start")
            return self._pid, "2026-10-19T12:34:56.123456789Z"
        def recheck(self):
            events.append("recheck")
            return hashlib.sha256(self.raw).hexdigest(), self._pid, "2026-10-19T12:34:56.123456789Z"
        def close(self):
            if self._id is not None and not self.closed:
                events.append("cleanup_exact_id")
                self.cleanup_obligation = "unverified" if mode == "cleanup_failure" else "none"
            self.closed = True
    scope = SimpleNamespace(begin=lambda timing: events.append("pids_begin"), end=lambda: events.append("pids_end"))
    broker = RootBroker(endpoint, Runtime(), intent, account, options, object(), now + 10, now + 200, now + 210,
                        time.monotonic, lambda: False, custody_factory=Custody, pids_scope=scope)
    try:
        broker.serve()
        assert mode in ("normal", "large") and broker.complete
    except (ProtocolError, LifecycleError):
        assert mode in ("eof", "unknown_create", "bad_digest", "cleanup_failure")
        assert not broker.complete
    assert events[-1] == "runtime_closed"
    assert events.count("cleanup_exact_id") == (0 if mode == "unknown_create" else 1)
    if mode == "normal":
        assert events.index("held_before_database") < events.index("database") < events.index("bound") < events.index("start")
        assert events.count("recheck") == 4 and events.count("pids_begin") == events.count("pids_end") == 1


class RootSourceAccountingTests(unittest.TestCase):
    def test_connected_old_refusal_and_unpatched_candidate_are_fixture_only(self):
        candidate = coordinator.ROLE_PLAN
        old_bytes = {"root_lane": 400000, "caller_lane": 200000, "emitter": 448576}
        original = tuple((role, scope, replace(allowance, source_bytes=old_bytes[role])) if role in old_bytes
                         else (role, scope, allowance) for role, scope, allowance in candidate)
        for plan in (original, candidate):
            self.assertEqual(sum(allowance.source_bytes for _role, scope, allowance in plan if scope == "outer"), 1048576)
            lanes = ("upstream-rootful",) if plan is original else ("upstream-rootful", "upstream-rootless", "debian11-rootful", "debian11-rootless")
            for lane in lanes:
                allocation = patch.object(coordinator, "ROLE_PLAN", plan) if plan is original else nullcontext()
                with self.subTest(original=plan is original, lane=lane), allocation:
                    self.assertIs(coordinator.ROLE_PLAN, plan)
                    result = self.connected_trace(lane)
                    if plan is original:
                        self.assertIsInstance(result["failure"], coordinator.CoordinationError)
                        self.assertTrue(result["caller"].scope.lane.poisoned)
                        self.assertFalse(result["emitted"])
                        refusal = result["refusals"][0]
                        self.assertEqual((refusal["role"], refusal["site"], refusal["phase"]),
                                         ("caller_lane", "phase_read", "emitter"))
                        self.assertGreater(refusal["used"] + refusal["requested"], refusal["cap"])
                        self.assertLessEqual(refusal["io_used"] + refusal["io_requested"], refusal["io_cap"])
                    else:
                        self.assertIsNone(result["failure"], result["failure"])
                        self.assertEqual(result["refusals"], [])
                        self.assertEqual(result["caller"].state, "closed")
                        self.assertTrue(result["caller"].final_verified)
                        self.assertTrue(result["caller"].trace_root.broker.complete)
                        self.assertEqual(set(result["consumers"]), {"reader", "emitter"})
                        self.assertTrue(result["emitted"])
                    self.assertEqual(result["caller"].trace_root.broker.custody.cleanup_obligation, "none")
                    self.assertEqual(result["caller"].trace_root.recovery.used.native_calls, 4)
                    owner = result["caller"]
                    budgets = (owner.scope.lane, owner.scope.pids, owner.trace_root.lane, owner.trace_root.pids, owner.trace_root.recovery)
                    self.assertEqual(sum(item.used.source_bytes for item in budgets), sum(size for _role, _site, size in result["charges"]))
                    self.assertEqual(sum(size for _role, _site, size in result["charges"]),
                                     sum(sum(totals.values()) for totals in result["phase_source_bytes"].values()))
                    if not hasattr(self, "connected_source_traces"):
                        self.connected_source_traces = {}
                    self.connected_source_traces[("original" if plan is original else "candidate") + ":" + lane] = {
                        "state": owner.state, "roles": {item.reservation.role: vars(item.used) for item in budgets},
                        "consumers": result["consumers"], "phase_bytes": owner.phase_stats,
                        "phase_source_bytes": result["phase_source_bytes"], "refusals": result["refusals"],
                        "source_charge_sites": sorted(set(site for _role, site, _size in result["charges"]))}
        self.assertIs(coordinator.ROLE_PLAN, candidate)

    def connected_trace(self, lane):
        """Fixture accounting, not native or variable-payload qualification.

        Executes the actual relay, six canonical phases, root protocol, source
        loaders, reader/emitter mains and exact-ID recovery. Native responses
        and complete proof inputs are authored, the producer is a tiny context
        consumer, executable/config rechecks are no-ops, and only the original
        OCI inode's UID is projected to root. Metadata I/O is not qualified.
        """
        import native_outer_canonical as canonical
        from test_native_evidence import NativeEvidenceTests, HEALTH_FIXTURE_IMAGE, RUN_ID
        from test_native_outer_authority import bind_proof_boundary
        from test_native_outer_lifecycle import NONCE
        root = Path(__file__).resolve().parents[1]
        candidate = subprocess.run(("git", "-C", str(root), "rev-parse", "HEAD"), capture_output=True, text=True, check=True).stdout.strip()
        records = json.loads((root / "docs/native-image-defaults/20261019-accounts-v1.json").read_bytes())["images"]
        fixture_pin = canonical.re.findall(rb"^FIXTURE_IMAGE='([^']+)'$", (root / "scripts/native-conformance.sh").read_bytes(), canonical.re.M)[0].decode()
        image = next(item["canonical_reference"] for item in records if item["lane"] == lane and item["architecture"] == "amd64")
        version = {"Version": "20.10.5" if lane.startswith("debian11-") else "29.8.1",
                   "ApiVersion": "1.41" if lane.startswith("debian11-") else "1.56", "MinAPIVersion": "1.12"}
        package = "20.10.5+dfsg1-1+deb11u2" if lane.startswith("debian11-") else ""
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            self.trace_stack = stack
            charges, refusals, phase_source_bytes = [], [], {}
            phase = ["bootstrap"]
            def observe(method):
                def call(budget, *arguments, **keywords):
                    before, frame = budget.used.source_bytes, inspect.currentframe().f_back
                    while frame.f_code.co_name in ("debit", "consume", "bounded_source_io", "fail"):
                        frame = frame.f_back
                    site = frame.f_code.co_name
                    try:
                        return method(budget, *arguments, **keywords)
                    except BaseException:
                        if method.__name__ == "debit":
                            refusals.append({"role": budget.reservation.role, "site": site, "phase": phase[0],
                                             "used": before, "requested": keywords.get("source_bytes", 0),
                                             "cap": budget.reservation.allowance.source_bytes,
                                             "io_used": budget.used.io_calls, "io_requested": keywords.get("io_calls", 0),
                                             "io_cap": budget.reservation.allowance.io_calls})
                        raise
                    finally:
                        if budget.used.source_bytes != before:
                            delta = budget.used.source_bytes - before
                            charges.append((budget.reservation.role, site, delta))
                            totals = phase_source_bytes.setdefault(phase[0], {})
                            totals[budget.reservation.role] = totals.get(budget.reservation.role, 0) + delta
                return call
            stack.enter_context(patch.object(ReservedBudget, "debit", observe(ReservedBudget.debit)))
            stack.enter_context(patch.object(ReservedBudget, "_settle_source", observe(ReservedBudget._settle_source)))
            actual_phase_read = canonical.phase_read
            phases = iter(("setup", "producer", "reader", "emitter", "final", "teardown"))
            def read_phase(*arguments, **keywords):
                # Includes the attempted phase's prepaid relay traffic and any
                # fault cleanup. Observes only; no allowance or I/O is changed.
                phase[0] = next(phases)
                return actual_phase_read(*arguments, **keywords)
            stack.enter_context(patch.object(canonical, "phase_read", read_phase))
            directory = Path(temporary) / ("dockerlens-native." + RUN_ID)
            directory.mkdir(mode=0o700)
            fixture_directory = SimpleNamespace(name=str(directory), cleanup=lambda: None)
            with patch("test_native_evidence.tempfile.TemporaryDirectory", return_value=fixture_directory):
                prepared, old_output = NativeEvidenceTests.run_emit(self, version, image=image, sha=candidate, lane=lane,
                                                                  mode=lane.rsplit("-", 1)[1], package=package)
            self.assertEqual(prepared.returncode, 0, prepared.stderr)  # Fixture construction, not fit evidence.
            old_output.unlink()
            for old, new in (("shapes", "target-shapes"), ("source", "source-probes"), ("network", "network-probes"),
                             ("volume", "volume-probes"), ("volume-label", "volume-label-probes"), ("identity", "identity-probes")):
                (directory / (old + ".json")).rename(directory / (new + ".json"))
            def current_fixture(value):
                if type(value) is str:
                    return fixture_pin if value == HEALTH_FIXTURE_IMAGE else value
                if type(value) is dict:
                    return {key: current_fixture(item) for key, item in value.items()}
                return list(map(current_fixture, value)) if type(value) is list else value
            for source in directory.glob("*.json"):
                source.write_text(json.dumps(current_fixture(json.loads(source.read_bytes())), separators=(",", ":")), encoding="utf-8")
            (directory / "diagnostics/daemon.log").unlink(missing_ok=True)
            evidence = Path(temporary) / "evidence"
            output = evidence / (lane + ".json")
            metadata = [str(directory), candidate, RUN_ID, lane, version["Version"], version["ApiVersion"],
                        lane.rsplit("-", 1)[1], package, fixture_pin, image, "f" * 64, "1000" if lane.endswith("rootless") else "0"]
            names = ("version", "target-shapes", "source-probes", "network-probes", "volume-probes", "volume-label-probes",
                     "identity-probes", "port-probes", "health-metadata", "network-attachments-v1", "bind-relabel-config-v1")
            requests = [["setup", str(directory), RUN_ID, lane, image], ["producer", *metadata, "a" * 64], ["reader", *metadata],
                        ["emitter", *(str(directory / (name + ".json")) for name in names), str(directory), str(output), lane,
                         image, metadata[6], package, candidate, RUN_ID], ["final"], ["teardown"]]
            script = Path(temporary) / "phases.sh"
            relay = shlex.join(("/usr/bin/python3", "-E", "-s", str(root / "scripts/native_outer_canonical.py"), "relay"))
            script.write_text("set -euo pipefail\ncoproc TRACE_RELAY { exec " + relay + ' "$DOCKERLENS_CANONICAL_REPLY_FD" "$DOCKERLENS_CANONICAL_REQUEST_FD"; }\n'
                              'exec {DOCKERLENS_CANONICAL_REQUEST_FD}>&-\nexec {DOCKERLENS_CANONICAL_REPLY_FD}<&-\n'
                              'unset DOCKERLENS_CANONICAL_REQUEST_FD DOCKERLENS_CANONICAL_REPLY_FD\nr=${TRACE_RELAY[0]}; w=${TRACE_RELAY[1]}\n' +
                              "\n".join(shlex.join(("/usr/bin/python3", "-E", "-s", str(root / "scripts/native_outer_canonical.py"), *request)) +
                                        ' <&"$r" >&"$w"' for request in requests) + "\n", encoding="utf-8")
            actual_type, actual_role = canonical.Canonical, coordinator.run_private_role
            holder, consumers = {}, {}
            def factory(*arguments, **keywords):
                value = actual_type(*arguments, **keywords)
                holder["caller"] = value
                def spawn_broker(argv, **_options):
                    binding = argv[-14:]
                    self.assertEqual(tuple(binding[:10]), (value.session, candidate, "github_actions", "123", "1", lane,
                                                          RUN_ID, NONCE, image, str(directory)))
                    self.assertEqual(int(binding[-1]), value.deadline_ns)
                    value.trace_architecture = binding[10]
                    value.trace_deadlines = tuple(int(item) / 1e9 for item in argv[-3:])
                    return self.root_trace(lane, directory, connected=value)
                value.spawn = spawn_broker
                return value
            original_random = os.urandom
            stack.enter_context(patch.object(canonical.os, "urandom", side_effect=lambda size: bytes.fromhex(NONCE)
                                             if holder and size == 32 else original_random(size)))
            # Counter-only observer: actual consumer main/authority/role budgets
            # run unchanged. Its small numeric stdout is additionally charged to
            # BOTH child and caller; no private source/context values are sent.
            observer = '''import json,runpy,sys
sys.path.insert(0,sys.argv[1]);sys.argv=sys.argv[2:]
import native_outer_coordinator as c
seen=[];original=c.consumer_budget
def observe(*a,**kw):
 b=original(*a,**kw);seen.append(b);return b
c.consumer_budget=observe
runpy.run_path(sys.argv[0],run_name="__main__")
b=seen[0];report={"role":b.reservation.role,"bytes":b.used.source_bytes,"io":b.used.io_calls}
raw=json.dumps(report,separators=(",",":")).encode()+b"\\n"
b.debit(source_bytes=len(raw),io_calls=1)
sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()
'''
            def run_role(argv, environment, raw, budget, deadline):
                if argv[0] == "/bin/bash":
                    proof = directory / "pids-limit-v2.json"
                    value = json.loads(proof.read_bytes())
                    bind_proof_boundary(value, json.loads(raw)["boundary"])
                    proof.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")
                    fake = "import sys\nn=0\nwhile True:\n p=sys.stdin.buffer.raw.read(min(4096,131073-n));n+=len(p)\n if not p:break\n assert n<=131072\n"
                    return actual_role((sys.executable, "-c", fake), environment, raw, budget, deadline)
                chunks, descriptors, original_read = [], set(), os.read
                def spawn(_argv, **options):
                    child = subprocess.Popen((sys.executable, "-E", "-s", "-c", observer, str(root / "scripts"), *argv[3:]), **options)
                    descriptors.add(child.stdout.fileno())
                    return child
                def read(descriptor, maximum):
                    part = original_read(descriptor, maximum)
                    if descriptor in descriptors:
                        chunks.append(part)
                    return part
                with patch.object(coordinator.os, "read", read):
                    actual_role(argv, environment, raw, budget, deadline, spawn=spawn)
                report = json.loads(b"".join(chunks))
                report["observer_bytes"] = len(b"".join(chunks))
                cap = next(allowance.source_bytes for role, _scope, allowance in coordinator.ROLE_PLAN if role == report["role"])
                self.assertLessEqual(report["bytes"] + report["observer_bytes"], cap)
                consumers[report["role"]] = report
            stack.enter_context(patch.object(canonical, "Canonical", side_effect=factory))
            stack.enter_context(patch.object(canonical, "run_private_role", run_role))
            stack.enter_context(patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
                                                      "DOCKERLENS_NATIVE_EVIDENCE_DIR": str(evidence)}))
            failure = None
            try:
                canonical.launch(script, lane)
            except Exception as error:
                failure = error
            self.assertLess(sum(path.stat().st_size for path in Path(temporary).rglob("*") if path.is_file()), 3 * 1048576)
            return {"caller": holder["caller"], "consumers": consumers, "failure": failure, "emitted": output.exists(),
                    "charges": charges, "refusals": refusals, "phase_source_bytes": phase_source_bytes}

    def test_complete_root_actor_authored_capture_trace_is_not_whole_caller_fit(self):
        # Only native command responses and root-owned metadata are synthetic.
        # The source loader, native collector, normalization, real OCI file
        # custody, framed root protocol and both phase budgets execute normally.
        # Executable/config metadata rechecks are excluded (zero source bytes
        # in production). This is NOT a complete connected caller/consumer fit.
        for lane in ("upstream-rootful", "upstream-rootless", "debian11-rootful", "debian11-rootless"):
            with self.subTest(lane=lane), tempfile.TemporaryDirectory() as temporary:
                self.root_trace(lane, Path(temporary))

    def root_trace(self, lane, directory, *, connected=None):
        from native_outer_bootstrap import build_bootstrap_argv
        from test_native_pids_limit_v2_proof import fixture as proof_fixture
        records = json.loads((Path(__file__).resolve().parents[1] / "docs/native-image-defaults/20261019-accounts-v1.json").read_bytes())["images"]
        architecture = "amd64" if connected is None else connected.trace_architecture
        source_context = proof_fixture(lane)["context"]
        if connected is not None:
            source_context["candidate_sha"] = connected.candidate
        source_context["outer"]["image"] = next(item["canonical_reference"] for item in records
                                               if item["lane"] == lane and item["architecture"] == architecture)
        context, _expected, _fixture_account, options, _prefix, _proof = authority_fixture(lane, directory, source_context, reviewed=True,
                                                                                        architecture=architecture)
        if connected is not None:
            (directory / "diagnostics/daemon.log").unlink()
        intent = CreateIntent(**context["source"]["intent"])
        now = time.monotonic()
        session = secrets.token_hex(32) if connected is None else connected.session
        end = time.monotonic_ns() + 300_000_000_000 if connected is None else connected.deadline_ns
        startup, custody, cleanup = (now + 60, now + 250, now + 300) if connected is None else connected.trace_deadlines
        book, roles = coordinator.prepare_reservations(session, end) if connected is None else (connected.book, connected.roles)
        def budget(role):
            if connected is None:
                reservation = book.claim_before_spawn(roles[role])
            else:
                self.assertIn(roles[role].sequence, book._claimed)  # Parent admitted before spawn.
                reservation = coordinator.fixed_reservation(session, role, end)
            return ReservedBudget(reservation, time.monotonic_ns, lambda: False)
        root_lane, root_pids, recovery = budget("root_lane"), budget("root_pids"), budget("root_recovery")
        caller_lane, caller_pids = ((budget("caller_lane"), budget("caller_pids")) if connected is None else
                                    (connected.scope.lane, connected.scope.pids))
        root_scope = coordinator.ScopeBudget(root_lane, root_pids)
        caller_scope = coordinator.ScopeBudget(caller_lane, caller_pids) if connected is None else connected.scope
        account = coordinator.candidate_account(lane, architecture, intent.image_ref, budget=root_scope)
        database = payload_read("initialize", context["source"]["database"])
        image = {"digest": account.image_digest, "platform_digest": account.platform_digest,
                 "config_digest": account.config_digest, "architecture": account.architecture,
                 "config": context["source"]["preflight"]["semantic"]["config"]}
        expected = derive_launch(intent, image, account, source_defaults(intent, account, database, options))
        oci = directory / "config.json" if connected is None else directory.parent / "owned-bundle/config.json"
        oci.parent.mkdir(mode=0o700, exist_ok=True)
        oci.write_bytes(payload_read("bind_expectation", context["source"]["oci"]).raw)
        oci.chmod(0o600)
        oci_identity = (oci.stat().st_dev, oci.stat().st_ino)
        real_stat, real_fstat = os.stat, os.fstat
        def project(info):
            if (info.st_dev, info.st_ino) != oci_identity:
                return info
            values = {name: getattr(info, name) for name in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")}
            return SimpleNamespace(**values, st_uid=0)
        running, captures = [False], []
        argv = build_bootstrap_argv(intent.nonce, list(expected.original_argv))
        def native_capture(command):
            # Authored native-shaped values come from the public image source
            # facts and fixed recipe, never from the target OCI document.
            if command[0] == "pull":
                return b"", 0
            if command[0] == "info":
                value = {"host": {"os": "linux", "security": {"rootless": False}, "serviceIsRemote": False,
                                  "ociRuntime": {"name": "crun", "path": "/usr/bin/crun", "version": "crun version 1.14.1"},
                                  "cgroupManager": "systemd", "cgroupVersion": "v2"}, "version": {"Version": "4.9.3"}}
            elif command[:2] == ("image", "inspect"):
                value = [{"Id": account.config_digest[7:], "Digest": account.platform_digest,
                          "RepoDigests": context["source"]["preflight"]["native_repo_digests"],
                          "Os": "linux", "Architecture": architecture, "User": account.user_text,
                          "RootFS": {"Type": "layers", "Layers": list(account.ordered_layer_diff_ids)},
                          "Config": {key: value for key, value in image["config"].items() if value}}]
            elif command[0] == "create":
                return (context["binding"]["outer_id"] + "\n").encode(), 0
            elif command[:2] == ("container", "init") or command[0] == "rm":
                return b"", 0
            elif command[0] == "start":
                running[0] = True
                if connected is not None:
                    (directory / "diagnostics/daemon.log").write_bytes(_prefix)
                return b"", 0
            elif command[:2] == ("container", "exists"):
                return b"", 1
            elif command[:2] == ("volume", "inspect"):
                value = [{"Name": intent.data_volume, "Labels": {"io.dockerlens.native-run": intent.owner},
                          "Driver": "local", "Options": {}, "Mountpoint": database.owned_volume["mountpoint"]}]
            else:
                self.assertEqual(command[:2], ("container", "inspect"))
                value = [{"Id": context["binding"]["outer_id"], "Name": intent.name,
                          "Image": account.config_digest[7:], "ImageDigest": account.platform_digest, "OCIRuntime": "crun",
                          "Path": argv[0], "Args": argv[1:], "RestartCount": 0, "OCIConfigPath": str(oci),
                          "StaticDir": database.static_dir, "HostnamePath": database.hostname_path,
                          "HostsPath": database.hosts_path, "ResolvConfPath": database.resolv_conf_path,
                          "Config": {"Labels": {"io.dockerlens.native-run": intent.owner}, "Entrypoint": "/bin/sh",
                                     "Env": list(expected.environment), "WorkingDir": expected.cwd, "Tty": False},
                          "HostConfig": {"Privileged": True, "Memory": 4294967296, "CpuPeriod": 100000,
                                         "CpuQuota": 200000, "PidsLimit": 512, "LogConfig": {"Type": "k8s-file", "Path": str(directory / "diagnostics/daemon.log")},
                                         "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0}},
                          "State": {"Status": "running" if running[0] else "initialized", "Running": running[0],
                                    "Paused": False, "Restarting": False, "OOMKilled": False, "Dead": False, "Error": "", "ExitCode": 0,
                                    "Pid": 2345, "StartedAt": "2026-10-19T12:34:56.123456789Z" if running[0] else "0001-01-01T00:00:00Z",
                                    "FinishedAt": "0001-01-01T00:00:00Z"}}]
            return json.dumps(value, separators=(",", ":")).encode(), 0
        def spawn(timed, **keywords):
            marker = next(index for index, item in enumerate(timed) if item.startswith("--default-mounts-file="))
            command = timed[marker + 1:]
            raw, status = native_capture(command)
            captures.append((command[:2], len(raw)))
            return subprocess.Popen((sys.executable, "-c", "import os,sys;os.write(1,bytes.fromhex(sys.argv[1]));raise SystemExit(int(sys.argv[2]))",
                                     raw.hex(), str(status)), **keywords)
        executables = [SimpleNamespace(chain=SimpleNamespace(path=path), recheck=lambda: None,
                                       recovery_recheck=lambda *_args: None, close=lambda: None)
                       for path in ("/usr/bin/podman", "/usr/bin/crun", "/usr/bin/timeout")]
        configuration = SimpleNamespace(recheck=lambda: None, recovery_recheck=lambda *_args: None, close=lambda: None)
        runtime = FixedPodmanRuntime(intent, account, BoundedNativeProcess(root_scope, spawn=spawn), BoundedNativeProcess(recovery, spawn=spawn),
                                     {"PATH": "/usr/bin:/bin", "HOME": "/root", "LANG": "C", "LC_ALL": "C", "CONTAINERS_CONF": "/owned/conf"},
                                     "/owned/conf", "/owned/mounts", "/owned/hooks", executables, configuration)
        binding = Binding(session, context["binding"]["candidate_sha"], "123", "1", context["binding"]["intent_digest"], account.image_digest)
        request_read, request_write = os.pipe()
        reply_read, reply_write = os.pipe()
        def endpoint(role, read_fd, write_fd, scope):
            return Endpoint(role, binding, read_fd, write_fd, Ledger(30000, 1048576, startup, custody, cleanup,
                                                                   cleanup, time.monotonic, lambda: False, reserved_budget=scope),
                            pids_window=PidsWindow(int(custody * 1e9), time.monotonic_ns))
        client = endpoint("client", reply_read, request_write, caller_scope) if connected is None else None
        server = endpoint("broker", request_read, reply_write, root_scope)
        broker = RootBroker(server, runtime, intent, account, options, root_scope, startup, custody, cleanup,
                            time.monotonic, lambda: False, pids_scope=root_scope)
        errors = []
        def serve():
            try:
                broker.serve()
            except BaseException as error:
                errors.append(error)
        if connected is not None:
            self.trace_stack.enter_context(patch.object(lifecycle_module.os, "stat", side_effect=lambda *args, **kwargs: project(real_stat(*args, **kwargs))))
            self.trace_stack.enter_context(patch.object(lifecycle_module.os, "fstat", side_effect=lambda *args, **kwargs: project(real_fstat(*args, **kwargs))))
            thread = Thread(target=serve)
            thread.start()
            connected.trace_root = SimpleNamespace(lane=root_lane, pids=root_pids, recovery=recovery, broker=broker,
                                                    wire=server.ledger, captures=captures, oci=oci, errors=errors)
            def wait(timeout):
                thread.join(timeout=min(timeout, 5))
                self.assertFalse(thread.is_alive())
                return int(bool(errors))
            return SimpleNamespace(stdin=os.fdopen(request_write, "wb", buffering=0),
                                   stdout=os.fdopen(reply_read, "rb", buffering=0), wait=wait)
        with patch.object(lifecycle_module.os, "stat", side_effect=lambda *args, **kwargs: project(real_stat(*args, **kwargs))), \
             patch.object(lifecycle_module.os, "fstat", side_effect=lambda *args, **kwargs: project(real_fstat(*args, **kwargs))):
            thread = Thread(target=serve)
            thread.start()
            try:
                def exchange(verb, payload=None):
                    client.request(verb, payload)
                    return client.receive().payload
                exchange("preflight")
                exchange("create")
                exchange("initialize")
                exchange("bind_expectation", ExpectationClaim(context["binding"]["expectation_digest"]))
                exchange("start")
                start = time.monotonic_ns()
                timing = PidsTiming(start, start + 180_000_000_000)
                caller_scope.begin(timing)
                exchange("begin_pids", timing)
                for verb in ("pids_before_producer", "pids_before_reader", "seal_pids"):
                    exchange(verb)
                caller_scope.end()
                exchange("recheck")  # Mandatory optional-emitter custody check.
                exchange("recheck")  # Mandatory final custody check.
                exchange("teardown")
            finally:
                client.close()
                thread.join(timeout=5)
                server.close()
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertTrue(broker.complete)
        self.assertEqual((root_lane.used.native_calls, root_pids.used.native_calls, recovery.used.native_calls), (12, 3, 4))
        self.assertEqual(len(captures), 19)
        record_bytes = sum((Path(__file__).resolve().parents[1] / "docs/native-image-defaults" / name).stat().st_size for name in
                           ("20261019-accounts-v1.json", "20261019-paths-v1.json", "podman493-source-binding-v1.json"))
        native_bytes = sum(size for _command, size in captures)
        oci_bytes = 12 * oci.stat().st_size
        self.assertEqual(server.ledger.bytes, client.ledger.bytes)
        self.assertEqual(root_lane.used.source_bytes + root_pids.used.source_bytes + recovery.used.source_bytes,
                         record_bytes + native_bytes + oci_bytes + server.ledger.bytes)
        self.assertLessEqual(root_lane.used.source_bytes, roles["root_lane"].allowance.source_bytes)
        self.assertFalse(root_lane._source_claims or root_pids._source_claims or recovery._source_claims)
        # Keep this partial trace inspectable by the primary without claiming
        # source-only fixture sizes bound genuine native JSON or whole actors.
        if not hasattr(self, "source_traces"):
            self.source_traces = {}
        self.source_traces[lane] = {"root_lane": vars(root_lane.used), "root_pids": vars(root_pids.used),
                                    "recovery": vars(recovery.used), "protocol_only_caller": vars(caller_lane.used),
                                    "native_capture_bytes": native_bytes, "source_record_bytes": record_bytes,
                                    "oci_recheck_bytes": oci_bytes, "protocol_bytes": server.ledger.bytes}


class SeparateBrokerTests(unittest.TestCase):
    def open(self, mode):
        context, _expected, account, options, _prefix, _proof = authority_fixture()
        read, write = os.pipe()
        inherited = fcntl.fcntl(read, fcntl.F_DUPFD, 100)
        os.set_inheritable(inherited, True)
        try:
            root = Path(__file__).resolve().parents[1]
            child = subprocess.Popen((sys.executable, "-c", "from test_native_outer_broker import broker_worker;import sys;broker_worker(sys.argv[1])", mode),
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
                                     start_new_session=True, cwd=root,
                                     env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(root / "scripts") + ":" + str(root / "tests")})
        finally:
            for descriptor in (read, write, inherited):
                os.close(descriptor)
        now = time.monotonic()
        binding = Binding(context["binding"]["session"], context["binding"]["candidate_sha"], "123", "1",
                          context["binding"]["intent_digest"], account.image_digest)
        endpoint = Endpoint("client", binding, child.stdout.fileno(), child.stdin.fileno(),
                            Ledger(10000, 1048576, now + 10, now + 200, now + 210, now + 210, time.monotonic, lambda: False),
                            pids_window=PidsWindow(int((now + 200) * 1e9), time.monotonic_ns))
        return child, endpoint, context, account, options

    def close(self, child, endpoint):
        endpoint.close()
        status = child.wait(timeout=5)
        error = child.stderr.read(4097)
        for stream in (child.stdin, child.stdout, child.stderr):
            try:
                stream.close()
            except OSError:
                pass
        self.assertEqual((status, error), (0, b""))

    def request(self, endpoint, verb, payload=None):
        endpoint.request(verb, payload)
        return endpoint.receive()

    def startup(self, endpoint, context, account, options, *, wrong_digest=False):
        self.request(endpoint, "preflight")
        self.request(endpoint, "create")
        database = self.request(endpoint, "initialize").payload
        intent = CreateIntent(**context["source"]["intent"])
        image = {"digest": account.image_digest, "platform_digest": account.platform_digest,
                 "config_digest": account.config_digest, "architecture": account.architecture,
                 "config": context["source"]["preflight"]["semantic"]["config"]}
        expected = derive_launch(intent, image, account, source_defaults(intent, account, database, options))
        digest = expectation_digest(expected, endpoint.id, endpoint.binding.intent_digest)
        return self.request(endpoint, "bind_expectation", ExpectationClaim("0" * 64 if wrong_digest else digest))

    def test_connected_phase_order_three_pids_rechecks_and_exact_teardown(self):
        child, endpoint, context, account, options = self.open("normal")
        try:
            self.startup(endpoint, context, account, options)
            self.request(endpoint, "start")
            now = time.monotonic_ns()
            self.request(endpoint, "begin_pids", PidsTiming(now, now + 180_000_000_000))
            for verb in ("pids_before_producer", "pids_before_reader", "seal_pids", "recheck", "teardown"):
                self.request(endpoint, verb)
        finally:
            self.close(child, endpoint)

    def test_large_oci_crosses_real_pipe_backpressure_without_sidecar(self):
        child, endpoint, context, account, options = self.open("large")
        try:
            receipt = self.startup(endpoint, context, account, options).payload
            self.assertEqual(len(receipt.raw), 65536)
            self.request(endpoint, "teardown")
        finally:
            self.close(child, endpoint)

    def test_eof_after_start_retains_exact_id_cleanup(self):
        child, endpoint, context, account, options = self.open("eof")
        self.startup(endpoint, context, account, options)
        self.request(endpoint, "start")
        self.close(child, endpoint)

    def test_unknown_create_wrong_digest_and_failed_cleanup_never_ack_success(self):
        for mode in ("unknown_create", "bad_digest", "cleanup_failure"):
            child, endpoint, context, account, options = self.open(mode)
            try:
                with self.assertRaises(ProtocolError):
                    if mode == "unknown_create":
                        self.request(endpoint, "preflight")
                        self.request(endpoint, "create")
                    else:
                        self.startup(endpoint, context, account, options, wrong_digest=mode == "bad_digest")
                        self.request(endpoint, "teardown")
            finally:
                self.close(child, endpoint)
