"""Exclusive root lifecycle dispatcher for the fixed outer instance.

The protocol exposes phases, never arbitrary argv, executable paths or native
JSON. EOF, malformed requests and failed replies all retain exact-ID cleanup.
"""

import hashlib
import os
import re
import signal
import sys
import time

from native_outer_broker_protocol import (Empty, OCIReceipt, PidsTiming, PreflightReceipt,
                                         RecheckedReceipt, StartedReceipt)
from native_outer_launch import derive_launch, expectation_digest, source_defaults
from native_outer_lifecycle import RootOCICustody, require


class RootBroker:
    def __init__(self, endpoint, runtime, intent, account, socket_options, custody_budget,
                 startup_deadline, custody_deadline, cleanup_deadline, clock, cancelled,
                 *, custody_factory=RootOCICustody, pids_scope=None):
        self.endpoint, self.runtime, self.intent, self.account = endpoint, runtime, intent, account
        self.socket_options, self.budget = socket_options, custody_budget
        self.deadlines = startup_deadline, custody_deadline, cleanup_deadline
        self.clock, self.cancelled = clock, cancelled
        self.custody_factory, self.pids_scope = custody_factory, pids_scope
        self.custody = self.database = self.expectation_digest = None
        self.complete = False

    def _launch(self, database):
        return derive_launch(self.intent, self.runtime.image.launch_image(), self.account,
                             source_defaults(self.intent, self.account, database, self.socket_options))

    def dispatch(self, message):
        verb = message.verb
        if verb == "preflight":
            receipt = self.runtime.preflight(self.deadlines[0])
            require(type(receipt) is PreflightReceipt)
            self.custody = self.custody_factory(self._launch(None), self.runtime.profile, self.runtime,
                                               self.intent.run_directory + "/diagnostics/daemon.log", self.budget,
                                               *self.deadlines, self.clock, self.cancelled)
            self.endpoint.respond(receipt)
        elif verb == "create":
            self.endpoint.respond(Empty(), container_id=self.custody.create())
        elif verb == "initialize":
            self.custody.initialize()  # Holds original OCI/ancestors NOW.
            self.database = self.runtime.database_receipt(self.deadlines[0])
            require(self.database.init_pid == self.custody._pid)
            self.endpoint.respond(self.database)
        elif verb == "bind_expectation":
            require(self.database is not None)
            expected = self._launch(self.database)
            bound = expectation_digest(expected, self.custody._id, self.endpoint.binding.intent_digest)
            # Independently compute and compare BEFORE adopting caller claim.
            require(message.payload.digest == bound)
            self.custody.bind_expectation(expected)
            self.runtime.expectation = expected
            self.expectation_digest = bound
            raw, info, pid = self.custody.original_oci()
            receipt = OCIReceipt(raw, info.device, info.inode, info.uid, info.mode, info.links,
                                 info.size, hashlib.sha256(raw).hexdigest(), pid)
            self.endpoint.respond(receipt, expectation_digest=bound)
        elif verb == "start":
            self.custody.arm()
            pid, started = self.custody.start()
            self.endpoint.respond(StartedReceipt(pid, started))
        elif verb == "begin_pids":
            require(type(message.payload) is PidsTiming and self.pids_scope is not None)
            self.pids_scope.begin(message.payload)
            self.endpoint.respond(message.payload)
        elif verb in ("recheck", "pids_before_producer", "pids_before_reader", "seal_pids"):
            sha256, pid, started = self.custody.recheck()
            self.endpoint.respond(RecheckedReceipt(sha256, pid, started))
            if verb == "seal_pids":
                self.pids_scope.end()
        elif verb == "teardown":
            self.custody.close()
            require(self.custody.cleanup_obligation == "none")
            self.endpoint.respond(Empty())
            self.complete = True
        else:
            require(False)

    def serve(self):
        try:
            while not self.complete:
                self.dispatch(self.endpoint.receive())
        finally:
            # A partial ACK/EOF cannot release the original cleanup obligation.
            # Cleanup uses a distinct prepaid original-deadline recovery slice.
            if self.custody is not None:
                self.custody.close()
            self.endpoint.close()
            self.runtime.close()
        require(self.complete)


def main(arguments):
    from native_outer_broker_protocol import Binding, Endpoint, Ledger, PidsWindow
    from native_outer_coordinator import (ReservedBudget, ScopeBudget, candidate_account, fixed_reservation,
                                          socket_mount_options)
    from native_outer_launch import CreateIntent, intent_digest
    from native_outer_runtime import BoundedNativeProcess, FixedPodmanRuntime, NativeExecutable, OwnedRuntimeConfiguration
    require(os.geteuid() == 0 and len(arguments) == 14)
    session, candidate, origin, ci_run, ci_attempt, lane, owner, nonce, image, directory, architecture, startup_ns, custody_ns, cleanup_ns = arguments
    require(origin in ("github_actions", "local_process"))
    if origin == "local_process":
        require(ci_run == ci_attempt == "")
        ci_run = ci_attempt = None
    else:
        require(all(re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None for value in (ci_run, ci_attempt)))
    startup, custody, cleanup = (int(value) / 1e9 for value in (startup_ns, custody_ns, cleanup_ns))
    now = time.monotonic()
    require(0 < startup - now <= 120 and startup <= custody < cleanup and cleanup - now <= 1800)
    cancelled = [False]
    for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(signum, lambda _signal, _frame: cancelled.__setitem__(0, True))
    stopped = lambda: cancelled[0]
    root_lane = ReservedBudget(fixed_reservation(session, "root_lane", int(cleanup_ns)), time.monotonic_ns, stopped)
    root_pids = ReservedBudget(fixed_reservation(session, "root_pids", int(cleanup_ns)), time.monotonic_ns, stopped)
    recovery = ReservedBudget(fixed_reservation(session, "root_recovery", int(cleanup_ns)), time.monotonic_ns, lambda: False)
    budget = ScopeBudget(root_lane, root_pids)
    # Explicit bounded source-backed FIPS admission: absence only; any presence
    # (including a link), inaccessible metadata or unexpected error refuses.
    root_lane.debit(io_calls=1)
    try:
        os.lstat("/etc/system-fips")
    except FileNotFoundError:
        pass
    else:
        require(False)
    account = candidate_account(lane, architecture, image, budget=root_lane)
    intent = CreateIntent(lane, owner, nonce, image, "dl-native-" + owner, "dl-native-data-" + owner,
                          "dl-native-net-" + owner, directory + "/socket", directory)
    binding = Binding(session, candidate, ci_run, ci_attempt, intent_digest(intent, account, candidate), account.image_digest, origin)
    configuration = OwnedRuntimeConfiguration(directory, budget, cleanup)
    executables = []
    try:
        for path in ("/usr/bin/podman", "/usr/bin/crun", "/usr/bin/timeout"):
            executables.append(NativeExecutable(path, budget, cleanup, time.monotonic, stopped))
        environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C", "LC_ALL": "C",
                       "CONTAINERS_CONF": configuration.config_path}
        runtime = FixedPodmanRuntime(intent, account, BoundedNativeProcess(budget, cancelled=stopped),
                                     BoundedNativeProcess(recovery), environment, configuration.config_path,
                                     configuration.mounts_path, configuration.hooks_path, executables, configuration)
        ledger = Ledger(30000, 1048576, startup, custody, cleanup, cleanup, time.monotonic, stopped, reserved_budget=budget)
        endpoint = Endpoint("broker", binding, 0, 1, ledger,
                            pids_window=PidsWindow(int(custody_ns), time.monotonic_ns))
        broker = RootBroker(endpoint, runtime, intent, account, socket_mount_options(intent.socket_source), budget,
                            startup, custody, cleanup, time.monotonic, stopped, pids_scope=budget)
        broker.serve()
    finally:
        configuration.close()
        for executable in executables:
            executable.close()


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Exception:
        raise SystemExit("outer broker refused") from None
