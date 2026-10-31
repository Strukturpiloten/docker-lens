"""Hermetic namespace-inspect transport controls; never enter a real namespace."""
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from test_native_daemon_uid_bridge import HOSTED
from test_native_net_probe import PROBE, SCRIPT


def closed_group_failure(stderr):
    pattern = (r"DOCKERLENS_SYNTHETIC_NAMESPACE_GROUP: phase=(setup|observe|receipt|absence|elapsed|teardown) "
               r"error=(json|wait_timeout|assertion|io|other|children_alive) cleanup=(complete|incomplete)")
    return next((line for line in stderr.splitlines() if re.fullmatch(pattern, line)),
                "closed process-group control failed: diagnostic=unavailable")


class NamespaceBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="dl-net-bridge-")
        self.addCleanup(self.temporary.cleanup)
        self.private = Path(self.temporary.name)
        self.tools = self.private / "tools"
        self.tools.mkdir(mode=0o700)
        for tool in ("timeout", "env", "bash", "python3", "dirname"):
            (self.tools / tool).symlink_to(Path(shutil.which(tool)).resolve())
        self.run = self.private / "held;not-shell"
        self.run.mkdir(mode=0o700)
        (self.run / "docker-client").mkdir(mode=0o700)
        self.trace = self.private / "trace"
        self.pids = self.private / "pids"
        self.outer = "dl-native-owned"
        self.cid = "a" * 64
        self.started = "2026-10-21T00:00:00Z"
        self.reply = f"{self.cid}|4321|{self.started}|true|owned\n"
        self.environment = {"PATH": str(self.tools), **HOSTED}

    def clients(self, reply=None, status=0, mode="normal", receipt_mode="atomic"):
        assert receipt_mode in ("atomic", "partial", "missing")
        receipt = (
            f" receipt=Path({str(self.pids)!r})\n"
            " pending=receipt.with_name(receipt.name+'.pending.'+str(os.getpid()))\n"
            " descriptor=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)\n"
            " with os.fdopen(descriptor,'w') as stream: json.dump([os.getppid(),os.getpid(),child.pid],stream)\n"
            " pending.replace(receipt)\n"
        )
        if receipt_mode == "partial":
            # Reproduce the former exists-before-JSON race deliberately. The
            # inspect owner's unchanged group kill must stop this owned writer.
            receipt = (f" descriptor=os.open({str(self.pids)!r},os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)\n"
                       " time.sleep(30)\n")
        elif receipt_mode == "missing":
            receipt = " time.sleep(30)\n"
        for engine in ("podman", "docker"):
            path = self.tools / engine
            path.write_text("#!/usr/bin/env python3\nimport json,os,signal,subprocess,sys,time\nfrom pathlib import Path\n"
                f"Path({str(self.trace)!r}).write_text(json.dumps({{'engine':{engine!r},'argv':sys.argv[1:]}}))\n"
                f"mode={mode!r}\n"
                "if mode in ('overflow','child-eof','cancelled','observer-cancel','hard-cancel'):\n"
                " child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])\n"
                + receipt +
                " if mode=='child-eof': raise SystemExit(0)\n"
                " if mode=='cancelled': os.kill(os.getpid(),signal.SIGTERM)\n"
                " if mode in ('observer-cancel','hard-cancel'): time.sleep(30)\n"
                " sys.stdout.write('x'*513); sys.stdout.flush(); time.sleep(30)\n"
                f"sys.stdout.write({self.reply if reply is None else reply!r})\nraise SystemExit({status})\n")
            path.chmod(0o700)

    def inspect(self, engine, changes=None):
        with mock.patch.dict(os.environ, {**self.environment, **(changes or {})}, clear=True):
            return PROBE.inspect(self.outer, "owned", engine, str(self.run))

    def test_exact_native_identity_format_and_both_backend_command_projections(self):
        self.clients()
        for engine in ("podman", "docker"):
            with self.subTest(engine=engine):
                self.assertEqual(self.inspect(engine), (self.cid, 4321, self.started))
                trace = json.loads(self.trace.read_text())
                prefix = ["--config", str(self.run / "docker-client"), "--host", "unix:///var/run/docker.sock"] if engine == "docker" else ["--remote=false"]
                self.assertEqual(trace, {"engine": engine, "argv": prefix + ["inspect", "--format", PROBE.INSPECT_FORMAT, self.outer]})
                self.assertEqual(list((self.run / "docker-client").iterdir()), [])
                self.assertFalse((self.run / "outer-runtime.json").exists())

    def test_ambient_selectors_and_missing_client_never_contact_any_ambient_runtime(self):
        ambient = self.private / "ambient"
        ambient.mkdir(mode=0o700)
        sentinel = self.private / "ambient-called"
        for engine in ("podman", "docker"):
            path = ambient / engine
            path.write_text(f"#!/bin/sh\nprintf called > {str(sentinel)!r}\nexit 97\n")
            path.chmod(0o700)
        for engine, changes in (("docker", {"DOCKER_HOST": "private-selector"}),
                                ("docker", {"GITHUB_REF": "untrusted"}),
                                ("podman", {"CONTAINER_HOST": "private-selector"})):
            self.clients()
            with self.subTest(engine=engine, selector=True), self.assertRaises(PROBE.ProbeFailure):
                self.inspect(engine, changes)
            self.assertFalse(self.trace.exists())
        for engine in ("podman", "docker"):
            self.clients()
            (self.tools / engine).unlink()
            self.assertIsNone(shutil.which(engine, path=self.environment["PATH"]))
            with mock.patch.dict(os.environ, {"PATH": str(ambient)}), self.assertRaises(PROBE.ProbeFailure):
                self.inspect(engine)
            self.assertFalse(self.trace.exists())
            self.assertFalse(sentinel.exists())

    def test_changed_or_malformed_native_or_failed_command_never_reaches_proc_or_probe(self):
        real_open = os.open
        def only_devnull(path, *args, **kwargs):
            # Popen legitimately opens its suppressed stderr, but namespace
            # observation must not reach any proc/net descriptor after refusal.
            if path != os.devnull:
                raise AssertionError("proc descriptor opened after refused identity")
            return real_open(path, *args, **kwargs)
        for engine in ("podman", "docker"):
            for reply, status in ((self.reply.replace("true", "false"), 0),
                                  (self.reply.replace("owned", "foreign"), 0),
                                  (self.reply.replace("4321", "0"), 0), (self.reply, 125)):
                self.clients(reply, status)
                cached = PROBE.Identity(self.cid, 4321, self.started, 777)
                arguments = [str(SCRIPT), "--engine", engine, "--directory", str(self.run),
                             "http", self.outer, cached.token(), "http://127.0.0.1:18110/index.html"]
                with self.subTest(engine=engine, status=status), \
                     mock.patch.dict(os.environ, self.environment, clear=True), \
                     mock.patch.object(sys, "argv", arguments), \
                     mock.patch.object(PROBE.shutil, "which", return_value="/closed-tool"), \
                     mock.patch.object(PROBE.os, "open", side_effect=only_devnull) as opened, \
                     mock.patch.object(PROBE.subprocess, "run") as entered, self.assertRaises(PROBE.ProbeFailure):
                    PROBE.main()
                self.assertTrue(all(call.args[0] == os.devnull for call in opened.call_args_list))
                entered.assert_not_called()

    def test_bridge_inspect_format_allowance_is_literal_not_an_arbitrary_query(self):
        self.clients()
        for engine in ("podman", "docker"):
            for template in ("{{json .Config}}", "{{.State.Pid}}", PROBE.INSPECT_FORMAT + " ",
                             PROBE.INSPECT_FORMAT.replace("io.dockerlens.native-run", "private-canary")):
                with self.subTest(engine=engine):
                    result = subprocess.run([str(self.tools / "bash"), str(SCRIPT.with_name("native-outer-command.sh")),
                        "--engine", engine, "--directory", str(self.run), "inspect", "--format", template, self.outer],
                        env=self.environment, capture_output=True, text=True, timeout=2)
                    self.assertEqual((result.returncode, result.stdout, result.stderr),
                                     (2, "", "native outer command refused\n"))
                    self.assertFalse(self.trace.exists())

    @staticmethod
    def group_driver():
        # A dedicated test driver adopts only its own descendants. This never
        # changes the unittest process, host policy or any native daemon.
        return r'''
import ctypes,importlib.util,json,os,subprocess,sys,time
assert ctypes.CDLL(None).prctl(36,1,0,0,0)==0
spec=importlib.util.spec_from_file_location('group_probe',sys.argv[1])
module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
start=time.monotonic();phase='setup';failure=None;process=None;cleanup='incomplete'
try:
 phase='observe'
 if sys.argv[5]=='hard-cancel':
  worker="import importlib.util,sys; s=importlib.util.spec_from_file_location('worker',sys.argv[1]);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m);m.inspect('dl-native-owned','owned',sys.argv[2],sys.argv[3])"
  process=subprocess.Popen([sys.executable,'-c',worker,*sys.argv[1:4]],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  while not os.path.exists(sys.argv[4]) and time.monotonic()-start<1: time.sleep(0.005)
  assert os.path.exists(sys.argv[4])
  # This PID is our still-unreaped direct child, not a recovered native PID.
  os.kill(process.pid,15);process.wait(timeout=1);category='cancelled'
 else:
  if sys.argv[5]=='observer-cancel':
   def interrupt(*args):
    while not os.path.exists(sys.argv[4]) and time.monotonic()-start<1: time.sleep(0.005)
    assert os.path.exists(sys.argv[4])
    raise KeyboardInterrupt
   module.select.select=interrupt
  try: module.inspect('dl-native-owned','owned',sys.argv[2],sys.argv[3])
  except module.ProbeFailure as error: category=error.category
  except KeyboardInterrupt: category='cancelled'
  else: raise AssertionError('synthetic group must refuse')
 phase='receipt'
 with open(sys.argv[4]) as stream: pids=json.load(stream)
 phase='absence'
 reap_deadline=max(time.monotonic()+0.75,start+3.25 if sys.argv[5]=='hard-cancel' else 0)
 late=False
 for pid in pids:
  while True:
   try: reaped,_=os.waitpid(pid,os.WNOHANG)
   except ChildProcessError:
    try: os.kill(pid,0)
    except ProcessLookupError: break
    else: raise AssertionError('owned descendant was not reaped')
   if reaped==pid: break
   if time.monotonic()>=reap_deadline:
    # waitpid proves this remains our owned unreaped child, not a reused PID.
    os.kill(pid,9);os.waitpid(pid,0);late=True;break
   time.sleep(0.005)
 assert not late
 phase='elapsed'
 assert time.monotonic()-start<3.5
 result={'category':category,'reaped':len(pids)}
except BaseException as error:
 kind=('json' if isinstance(error,json.JSONDecodeError) else
       'wait_timeout' if isinstance(error,subprocess.TimeoutExpired) else
       'assertion' if isinstance(error,AssertionError) else
       'io' if isinstance(error,OSError) else 'other')
 failure=(phase,kind)
finally:
 # Positive absence proof above always precedes teardown. Teardown cannot turn
 # a missing/malformed receipt or a failed assertion into a passing control.
 if process is not None and process.poll() is None:
  # Only this direct, still-unreaped Popen child may be signalled here.
  process.kill()
  try: process.wait(timeout=max(0.001,start+3.5-time.monotonic()))
  except subprocess.TimeoutExpired: pass
 while True:
  try: reaped,_=os.waitpid(-1,os.WNOHANG)
  except ChildProcessError: cleanup='complete';break
  if reaped!=0: continue
  if time.monotonic()-start>=3.5: break
  time.sleep(0.005)
 if cleanup!='complete' and failure is None: failure=('teardown','children_alive')
if failure is not None:
 print('DOCKERLENS_SYNTHETIC_NAMESPACE_GROUP: phase='+failure[0]+' error='+failure[1]+' cleanup='+cleanup,file=sys.stderr)
 raise SystemExit(1)
print(json.dumps(result))
'''

    @unittest.skipUnless(sys.platform == "linux", "Linux process-group reaping control")
    def test_two_second_group_budget_reaps_owned_error_timeout_and_cancelled_descendants(self):
        driver = self.group_driver()
        for engine in ("podman", "docker"):
            for mode in ("overflow", "child-eof", "cancelled", "observer-cancel", "hard-cancel"):
                with self.subTest(engine=engine, mode=mode):
                    self.pids.unlink(missing_ok=True)
                    self.clients(mode=mode)
                    started = time.monotonic()
                    result = subprocess.run([sys.executable, "-c", driver, str(SCRIPT), engine,
                        str(self.run), str(self.pids), mode], env=self.environment, capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 0, closed_group_failure(result.stderr))
                    self.assertEqual(self.pids.stat().st_mode & 0o777, 0o600)
                    category = "cancelled" if mode in ("observer-cancel", "hard-cancel") else "inspect"
                    self.assertEqual(json.loads(result.stdout), {"category": category, "reaped": 3})
                    self.assertLess(time.monotonic() - started, 4)

    @unittest.skipUnless(sys.platform == "linux", "Linux process-group reaping control")
    def test_observer_cancel_partial_or_missing_receipt_fails_with_closed_teardown_ack(self):
        for engine in ("podman", "docker"):
            for receipt_mode, phase, error in (("partial", "receipt", "json"),
                                                ("missing", "observe", "assertion")):
                with self.subTest(engine=engine, receipt_mode=receipt_mode):
                    self.pids.unlink(missing_ok=True)
                    self.clients(mode="observer-cancel", receipt_mode=receipt_mode)
                    result = subprocess.run([sys.executable, "-c", self.group_driver(), str(SCRIPT), engine,
                        str(self.run), str(self.pids), "observer-cancel"], env=self.environment,
                        capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr,
                        f"DOCKERLENS_SYNTHETIC_NAMESPACE_GROUP: phase={phase} error={error} cleanup=complete\n")

    def test_group_failure_context_accepts_only_closed_fixture_fields(self):
        valid = "DOCKERLENS_SYNTHETIC_NAMESPACE_GROUP: phase=receipt error=json cleanup=complete"
        self.assertEqual(closed_group_failure(valid), valid)
        for raw in (valid + " private-canary", valid.replace("receipt", "private-canary"),
                    "private-canary /private/path pid=123456"):
            self.assertEqual(closed_group_failure(raw),
                             "closed process-group control failed: diagnostic=unavailable")

    @unittest.skipUnless(sys.platform == "linux", "Linux process-group reaping control")
    def test_attach_custody_timeout_and_cancellation_cannot_escape_inspect_owner(self):
        closure = self.private / "closure"
        closure.mkdir(mode=0o700)
        for name in ("native-net-probe.py", "native-outer-command.sh", "native-outer-runtime.sh",
                     "native-outer-observation.py", "native-presence.py"):
            shutil.copyfile(SCRIPT.with_name(name), closure / name)
        stalled = self.private / "stalled-custody.py"
        stalled.write_text("import json,os,subprocess,sys,time\nfrom pathlib import Path\n"
            "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])\n"
            f"receipt=Path({str(self.pids)!r})\n"
            "pending=receipt.with_name(receipt.name+'.pending.'+str(os.getpid()))\n"
            "descriptor=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)\n"
            "with os.fdopen(descriptor,'w') as stream: json.dump([os.getpgrp(),os.getppid(),os.getpid(),child.pid],stream)\n"
            "pending.replace(receipt)\n"
            "time.sleep(30)\n")
        # Only the mirrored custody entry stalls. All other Python invocations
        # use the real interpreter, and clients remain authored private fakes.
        wrapper = self.tools / "python3"
        interpreter = wrapper.resolve()
        wrapper.unlink()
        wrapper.write_text('#!/bin/sh\nif [ "$1" = ' + shlex.quote(str(closure / "native-outer-observation.py")) +
            ' ] && [ "${2-}" = client-context ]; then\n exec ' + shlex.quote(str(interpreter)) + " " +
            shlex.quote(str(stalled)) + '\nfi\nexec ' + shlex.quote(str(interpreter)) + ' "$@"\n')
        wrapper.chmod(0o700)
        self.clients()
        for engine in ("podman", "docker"):
            for mode in ("timeout", "observer-cancel", "hard-cancel"):
                with self.subTest(engine=engine, mode=mode):
                    self.pids.unlink(missing_ok=True)
                    result = subprocess.run([sys.executable, "-c", self.group_driver(),
                        str(closure / "native-net-probe.py"), engine, str(self.run), str(self.pids), mode],
                        env=self.environment, capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 0, closed_group_failure(result.stderr))
                    self.assertEqual(self.pids.stat().st_mode & 0o777, 0o600)
                    category = "inspect" if mode == "timeout" else "cancelled"
                    self.assertEqual(json.loads(result.stdout), {"category": category, "reaped": 4})
                    self.assertFalse(self.trace.exists())

    def test_only_attached_helpers_drop_the_standalone_nested_timer(self):
        bridge = SCRIPT.with_name("native-outer-command.sh").read_text()
        attached = bridge.split('else\n', 1)[1].split('fi\n', 1)[0]
        self.assertLess(attached.index("native_outer_helper()"), attached.index("native_outer_attach"))
        self.assertNotIn("timeout", attached)
        preflight = bridge.split('if [[ $operation == preflight ]]; then\n', 1)[1].split('else\n', 1)[0]
        self.assertNotIn("native_outer_helper()", preflight)
        runtime = SCRIPT.with_name("native-outer-runtime.sh").read_text()
        helper = runtime.split("native_outer_helper() {\n", 1)[1].split("\n}", 1)[0]
        self.assertIn('"${native_outer_privilege[@]}" timeout --signal=TERM --kill-after=2s 8s', helper)
