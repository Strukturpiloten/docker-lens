"""Hermetic diagnostic-only controls: no runtime binary can be resolved."""
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "scripts/native-conformance.sh").read_text()
RUNTIME = (ROOT / "scripts/native-outer-runtime.sh").read_text()
CANARY = "protected-canary /private/socket 10.89.0.2 uid=987654"
APPARMOR_PROJECTION = (
    'inspect_reported_apparmor={{if ne (printf "%T" .AppArmorProfile) "string"}}unknown'
    '{{else if eq .AppArmorProfile "unconfined"}}unconfined'
    '{{else if eq .AppArmorProfile "docker-default"}}docker_default'
    '{{else if eq .AppArmorProfile ""}}empty{{else}}other{{end}}{{"\\n"}}'
)


def definition(name, source=SOURCE):
    start = source.index("\n" + name + "() {") + 1
    return source[start:source.index("\n}\n", start) + 3]


class FailureDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="dockerlens-closed-failure-")
        self.addCleanup(self.temporary.cleanup)
        self.private = Path(self.temporary.name)
        self.tools = self.private / "bin"
        self.tools.mkdir(mode=0o700)
        # No inherited PATH, runtime links, dynamic tool lookup or ambient sudo.
        for name, target in (("python3", sys.executable), ("timeout", "/usr/bin/timeout"),
                             ("bash", "/bin/bash"), ("grep", "/usr/bin/grep"),
                             ("sed", "/usr/bin/sed"), ("tail", "/usr/bin/tail"),
                             ("date", "/usr/bin/date")):
            (self.tools / name).symlink_to(target)
        self.client = self.tools / "held-client"
        self.trace = self.private / "trace"
        self.env = {"PATH": str(self.tools), "TRACE": str(self.trace)}

    def tool(self, path, body):
        path.write_text(f"#!{sys.executable}\n" + body)
        path.chmod(0o700)

    def client_reply(self, stdout="", status=0, stderr=""):
        self.tool(self.client, "import json,os,sys\nfrom pathlib import Path\n"
                  "Path(os.environ['TRACE']).write_text(json.dumps(sys.argv[1:]))\n"
                  f"sys.stdout.write({stdout!r});sys.stdout.flush()\n"
                  f"sys.stderr.write({stderr!r});sys.stderr.flush()\nraise SystemExit({status})\n")

    def shell(self, body, args=(), changes=None, timeout=4):
        return subprocess.run(["/bin/bash", "-c", body, "closed-control", *args],
                              env=self.env | (changes or {}), capture_output=True,
                              text=True, timeout=timeout)

    def attachment_body(self, privileged=False):
        vector = [str(self.client), "--config", "/held/config", "--host", "unix:///held/socket"]
        if privileged:
            vector = ["sudo", "-n", *vector]
            self.tool(self.tools / "sudo", "import json,os,sys\nfrom pathlib import Path\n"
                      "with Path(os.environ['SUDO_TRACE']).open('a') as trace: trace.write(json.dumps(sys.argv[1:])+'\\n')\n"
                      "assert sys.argv[1]=='-n'\nos.execvp(sys.argv[2],sys.argv[2:])\n")
        return ("set -euo pipefail\n" + definition("native_outer_command", RUNTIME)
                + definition("validated_outer_ipv4")
                + "native_outer_cmd=(" + " ".join(repr(item) for item in vector) + ")\n"
                + 'outer_network=owned\npodman_cmd=("${native_outer_cmd[@]}")\n'
                + 'diagnose_native_startup() { printf "held-state:%s held-profile:%s\\n" "$1" "${2:-unknown}" >&2; }\n'
                + 'validated_outer_ipv4 "$1" exact-owned-name\n')

    def test_attachment_positive_and_refusal_preserve_privileged_timer_and_exact_vector(self):
        projection = ('{{json .NetworkSettings.Networks}}|{{.State.Running}}|{{.State.Status}}|'
                      '{{.State.ExitCode}}|{{.State.OOMKilled}}|{{if .State.Error}}true{{else}}false{{end}}')
        prefix = ["--config", "/held/config", "--host", "unix:///held/socket"]
        for engine in ("docker", "podman"):
            query = ["inspect", "--format", (APPARMOR_PROJECTION if engine == "docker" else "") + projection,
                     "exact-owned-name"]
            for address, expected in (("10.89.0.2", 0), ("", 1)):
                self.client_reply(json.dumps({"owned": {"IPAddress": address}}) + "|true|running|0|false|false")
                sudo_trace = self.private / "sudo-trace"
                sudo_trace.unlink(missing_ok=True)
                result = self.shell(self.attachment_body(True), ["daemon"],
                                    {"SUDO_TRACE": str(sudo_trace), "native_outer_engine": engine})
                self.assertEqual(result.returncode, expected)
                self.assertEqual(json.loads(self.trace.read_text()), prefix + query)
                self.assertEqual(json.loads(sudo_trace.read_text()),
                                 ["-n", "timeout", "--signal=TERM", "--kill-after=2s", "10s",
                                  str(self.client), *prefix, *query])
                self.assertEqual(result.stdout, "10.89.0.2\n" if expected == 0 else "")
                self.assertEqual(result.stderr.count("held-state:"), expected)

    def test_docker_attachment_profiles_are_closed_optional_and_do_not_change_ip_or_state(self):
        for header, expected in (
            ("", "unknown"),
            *((f"inspect_reported_apparmor={value}\n", value)
              for value in ("unconfined", "docker_default", "other", "empty", "unknown")),
            (f"inspect_reported_apparmor={CANARY}\n", "unknown"),
            ("inspect_reported_apparmor=null\n", "unknown"),
            ('inspect_reported_apparmor={"secret":"protected-canary"}\n', "unknown"),
        ):
            for address, status in (("10.89.0.2", 0), ("", 1), ("127.0.0.1", 1)):
                with self.subTest(header=expected, address=address):
                    self.client_reply(header + json.dumps({"owned": {"IPAddress": address}})
                                      + "|false|exited|1|false|false")
                    result = self.shell(self.attachment_body(), ["daemon"],
                                        {"native_outer_engine": "docker"})
                    self.assertEqual(result.returncode, status)
                    query = json.loads(self.trace.read_text())
                    self.assertEqual(query[-4:-2], ["inspect", "--format"])
                    self.assertTrue(query[-2].startswith(APPARMOR_PROJECTION))
                    if status == 0:
                        self.assertEqual((result.stdout, result.stderr), ("10.89.0.2\n", ""))
                    else:
                        self.assertIn("held-state:running=false,status=exited,exit=nonzero,oom=false,error=false", result.stderr)
                        self.assertIn("held-profile:" + expected + "\n", result.stderr)
                    self.assertNotIn(CANARY, result.stdout + result.stderr)
                    self.assertNotIn("protected-canary", result.stdout + result.stderr)

    def test_docker_profile_reaches_startup_failure_without_another_inspect_or_raw_value(self):
        for profile in ("unconfined", "docker_default", "other", "empty", "unknown", CANARY):
            expected = profile if profile != CANARY else "unknown"
            reply = f"inspect_reported_apparmor={profile}\n" + '{"owned":{}}|false|exited|1|false|false'
            self.trace.unlink(missing_ok=True)
            self.tool(self.client, "import json,os,sys\nfrom pathlib import Path\n"
                      "with Path(os.environ['TRACE']).open('a') as trace: trace.write(json.dumps(sys.argv[1:])+'\\n')\n"
                      f"if 'inspect' in sys.argv: sys.stdout.write({reply!r})\n"
                      "else: sys.stderr.write('ERROR: permission denied\\n')\n")
            body = ("set -euo pipefail\n" + definition("native_outer_command", RUNTIME)
                    + definition("diagnose_native_startup") + definition("validated_outer_ipv4")
                    + f"native_outer_cmd=({str(self.client)!r})\n"
                    + "native_outer_engine=docker\nouter_network=owned\ncontainer=exact-owned-name\nlane=upstream-rootless\n"
                    + "validated_outer_ipv4 daemon exact-owned-name\n")
            result = self.shell(body)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, "")
            self.assertIn("category=daemon_permission families=daemon_permission preflight=none trace=unavailable "
                          f"rootlesskit_self_reexec=unobserved inspect_reported_apparmor={expected}\n", result.stderr)
            queries = [json.loads(line) for line in self.trace.read_text().splitlines()]
            self.assertEqual(len(queries), 2)
            self.assertEqual(queries[0][:2], ["inspect", "--format"])
            self.assertEqual(queries[1], ["logs", "--tail", "80", "exact-owned-name"])
            self.assertNotIn(CANARY, result.stdout + result.stderr)

    def test_attachment_retains_ip_predicate_and_only_failure_invokes_startup(self):
        state = "|true|running|0|false|false"
        for engine in ("docker", "podman"):
            for role in ("sidecar", "daemon"):
                for networks, category in (({"owned": {"IPAddress": "10.89.0.2"}}, None),
                                           ({"owned": {}}, "ipv4_missing"),
                                           ({"owned": {"IPAddress": "127.0.0.1"}}, "ipv4_nonprivate"),
                                           ({"owned": {}, "other": {}}, "network_extra")):
                    self.client_reply(json.dumps(networks) + state)
                    result = self.shell(self.attachment_body(), [role],
                                        {"CLIENT": str(self.client), "native_outer_engine": engine})
                    self.assertEqual(result.returncode, 0 if category is None else 1)
                    if category is None:
                        self.assertEqual((result.stdout, result.stderr), ("10.89.0.2\n", ""))
                    else:
                        self.assertEqual(result.stdout, "")
                        self.assertIn(f"role={role} category={category}", result.stderr)
                        self.assertEqual(result.stderr.count("held-state:"), int(role == "daemon"))
                        if role == "daemon":
                            self.assertIn("running=true,status=running,exit=zero,oom=false,error=false", result.stderr)
                        self.assertNotIn("10.89.0.2", result.stderr)

    def test_attachment_malformed_state_bound_and_command_status_remain_private(self):
        self.client_reply('{"owned":{}}|secret|secret|secret|secret|secret')
        result = self.shell(self.attachment_body(), ["daemon"], {"CLIENT": str(self.client)})
        self.assertIn("running=unknown,status=unknown,exit=unknown,oom=unknown,error=unknown", result.stderr)
        self.assertNotIn("secret", result.stderr)
        for raw, category, status in (("x" * 4097, "output_limit", 0),
                                       (CANARY, "json_shape", 0),
                                       (CANARY, "inspect_failed", 1),
                                       (CANARY, "inspect_failed", 124)):
            self.client_reply(raw, status)
            result = self.shell(self.attachment_body(), ["daemon"], {"CLIENT": str(self.client)})
            self.assertEqual(result.returncode, 1)
            self.assertIn("category=" + category, result.stderr)
            self.assertEqual(result.stderr.count("held-state:"), 1)
            self.assertNotIn(CANARY, result.stderr)

    def startup_body(self, privileged=False, held=True):
        vector = [str(self.client), "--config", "/held/config", "--host", "unix:///held/socket"]
        if privileged:
            vector = ["sudo", "-n", *vector]
            self.tool(self.tools / "sudo", "import json,os,sys\nfrom pathlib import Path\n"
                      "with Path(os.environ['SUDO_TRACE']).open('a') as trace: trace.write(json.dumps(sys.argv[1:])+'\\n')\n"
                      "assert sys.argv[1]=='-n'\nos.execvp(sys.argv[2],sys.argv[2:])\n")
        return ("set -euo pipefail\n" + definition("native_outer_command", RUNTIME)
                + definition("diagnose_native_startup")
                + "native_outer_cmd=(" + " ".join(repr(item) for item in vector) + ")\n"
                + 'podman_cmd=("${native_outer_cmd[@]}")\n'
                + 'container=exact-owned-name\nlane=upstream-rootless\n'
                + ('diagnose_native_startup "running=false,status=exited,exit=nonzero,oom=false,error=true"\n'
                   if held else 'diagnose_native_startup\n'))

    def test_startup_reuses_state_and_only_issues_existing_root_owned_bounded_logs_query(self):
        self.client_reply("ERROR: permission denied " + CANARY + "\n")
        for privileged in (False, True):
            sudo_trace = self.private / "sudo-trace"
            result = self.shell(self.startup_body(privileged), changes={"SUDO_TRACE": str(sudo_trace)})
            self.assertEqual(result.returncode, 0)
            self.assertEqual(json.loads(self.trace.read_text()),
                             ["--config", "/held/config", "--host", "unix:///held/socket",
                              "logs", "--tail", "80", "exact-owned-name"])
            if privileged:
                self.assertEqual(json.loads(sudo_trace.read_text()),
                                 ["-n", "timeout", "--signal=TERM", "--kill-after=2s", "10s",
                                  str(self.client), "--config", "/held/config", "--host", "unix:///held/socket",
                                  "logs", "--tail", "80", "exact-owned-name"])
            self.assertIn("category=daemon_permission", result.stderr)
            self.assertNotIn(CANARY, result.stdout + result.stderr)

    def test_late_state_query_is_same_projection_under_same_root_owned_ten_second_timer(self):
        self.tool(self.client, "import json,os,sys\nfrom pathlib import Path\n"
                  "with Path(os.environ['TRACE']).open('a') as trace: trace.write(json.dumps(sys.argv[1:])+'\\n')\n"
                  "if 'inspect' in sys.argv: print('exited|1|false')\n"
                  f"else: print({'ERROR: permission denied ' + CANARY!r})\n")
        sudo_trace = self.private / "sudo-trace"
        result = self.shell(self.startup_body(True, held=False), changes={"SUDO_TRACE": str(sudo_trace)})
        prefix = ["--config", "/held/config", "--host", "unix:///held/socket"]
        queries = [["inspect", "--format", "{{.State.Status}}|{{.State.ExitCode}}|{{.State.OOMKilled}}", "exact-owned-name"],
                   ["logs", "--tail", "80", "exact-owned-name"]]
        self.assertEqual([json.loads(line) for line in self.trace.read_text().splitlines()],
                         [prefix + query for query in queries])
        self.assertEqual([json.loads(line) for line in sudo_trace.read_text().splitlines()],
                         [["-n", "timeout", "--signal=TERM", "--kill-after=2s", "10s", str(self.client),
                           *prefix, *query] for query in queries])
        self.assertEqual(result.returncode, 0)
        self.assertIn("state=exited|1|false", result.stderr)
        self.assertNotIn(CANARY, result.stdout + result.stderr)

    def test_startup_collects_both_streams_with_closed_observed_families_not_normal_mentions(self):
        cases = (
            ("rootlesskit slirp4netns iptables storage driver overlay uid_map newuidmap ready\n", "", "unclassified", "none"),
            ("+ echo ERROR: uid_map failed\n++ echo ERROR: iptables failed\n+++ echo ERROR: storage driver failed\n", "", "unclassified", "none"),
            ("", "ERROR: failed to create default bridge: iptables: Permission denied\n", "daemon_network", "daemon_network"),
            ("", "newuidmap: write to uid_map failed: Operation not permitted\n", "rootless_uidmap", "rootless_uidmap"),
            ("", "/bin/sh: start-dockerd: not found\n", "rootless_launcher_unavailable", "rootless_launcher_unavailable"),
            ("", "ERROR: rootlesskit failed to setup network\n", "rootless_network", "rootless_network"),
            ("", "failed to mount overlay: invalid argument\n", "daemon_storage", "daemon_storage"),
            ("", "nsenter: reassociate to namespace ns/net failed: Operation not permitted\n", "daemon_permission", "daemon_permission"),
            ("", "failed to start daemon: unknown condition\n", "daemon_startup", "daemon_startup"),
            ("ERROR: failed to mount overlay: invalid argument\n", 'level=error msg="failed to create NAT chain: iptables"\n', "ambiguous", "daemon_storage,daemon_network"),
            ("ERROR: storage driver failed\n", "ERROR: overlay failed\n", "daemon_storage", "daemon_storage"),
            ("+ echo ERROR: iptables failed\nrootlesskit network ready\n", "ERROR: permission denied\n", "daemon_permission", "daemon_permission"),
            (" + ERROR: permission denied\n", "", "daemon_permission", "daemon_permission"),
        )
        for stdout, stderr, category, families in cases:
            with self.subTest(category=category, families=families):
                self.client_reply(stdout + CANARY + "\n", stderr=stderr + CANARY + "\n")
                result = self.shell(self.startup_body())
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr,
                    "inner daemon startup diagnosis: state=running=false,status=exited,exit=nonzero,oom=false,error=true "
                    f"stage=daemon category={category} families={families} preflight=none trace=unavailable "
                    "rootlesskit_self_reexec=unobserved inspect_reported_apparmor=unknown\n")
                self.assertNotIn(CANARY, result.stdout + result.stderr)

    def test_self_reexec_observation_matches_only_the_complete_verified_raw_line(self):
        prefix = "[rootlesskit:parent] error: failed to start the child: fork/exec /proc/self/exe: "
        denied = prefix + "permission denied"
        prohibited = prefix + "operation not permitted"
        positives = ((denied, "permission_denied"), (prohibited, "operation_not_permitted"),
                     (denied + "\n" + denied, "permission_denied"),
                     (denied + "\n" + prohibited, "ambiguous"))
        for text, expected in positives:
            self.client_reply(stderr=text + "\n")
            result = self.shell(self.startup_body())
            self.assertEqual(result.returncode, 0)
            self.assertIn(f" rootlesskit_self_reexec={expected} inspect_reported_apparmor=unknown\n", result.stderr)
            self.assertIn("category=daemon_permission families=daemon_permission preflight=none", result.stderr)
        negatives = (
            " " + denied, denied + " ", denied + "\r", denied + "\t", denied.upper(),
            "echo " + denied, "+ " + denied, "++ " + denied, "+++ " + denied,
            "\x1b[31m" + denied, denied + "\x1b[0m", denied + CANARY, CANARY + denied,
            denied.replace("/proc/self/exe", "/proc/1/exe"),
            denied.replace("/proc/self/exe", "/proc/self/exe2"),
            denied.replace("permission denied", "resource temporarily unavailable"),
            denied.replace("[rootlesskit:parent]", "[rootlesskit:child ]"),
        )
        for text in negatives:
            with self.subTest(text=text[:32]):
                self.client_reply(stderr=text + "\n")
                result = self.shell(self.startup_body())
                self.assertEqual(result.returncode, 0)
                self.assertIn(" rootlesskit_self_reexec=unobserved inspect_reported_apparmor=unknown\n", result.stderr)
                self.assertNotIn(CANARY, result.stdout + result.stderr)
        self.client_reply("ERROR: storage driver failed\n", stderr=denied + "\n")
        result = self.shell(self.startup_body())
        self.assertIn("category=ambiguous families=daemon_storage,daemon_permission preflight=none", result.stderr)
        self.assertIn("rootlesskit_self_reexec=permission_denied", result.stderr)

    def test_self_reexec_tail_requires_known_line_boundary_after_each_byte_cap(self):
        cap = 65536
        for errno, expected in (("permission denied", "permission_denied"),
                                ("operation not permitted", "operation_not_permitted")):
            line = "[rootlesskit:parent] error: failed to start the child: fork/exec /proc/self/exe: " + errno
            one_line_tail = line + "\n" + "x" * (cap - len(line) - 1)
            two_line_tail = line + "\n" + line + "\n" + "x" * (cap - 2 * (len(line) + 1))
            self.assertEqual(len(one_line_tail.encode()), cap)
            self.assertEqual(len(two_line_tail.encode()), cap)
            for prefix in (CANARY, "x" * (2 * cap) + CANARY):
                for payload, observation in (
                    (prefix + one_line_tail, "unobserved"),
                    (prefix + two_line_tail, expected),
                    (prefix + "\n" + one_line_tail, expected),
                ):
                    with self.subTest(errno=errno, repeated_trim=len(prefix) > cap,
                                      observation=observation):
                        # Independently force the retained bytes to start with
                        # valid-looking grammar. Only original LF boundaries
                        # decide whether that first record is complete.
                        self.assertTrue(payload.encode()[-cap:].startswith(line.encode()))
                        self.client_reply(stderr=payload)
                        result = self.shell(self.startup_body())
                        self.assertEqual(result.returncode, 0)
                        self.assertIn(f" rootlesskit_self_reexec={observation} inspect_reported_apparmor=unknown\n", result.stderr)
                        self.assertIn("category=daemon_permission families=daemon_permission preflight=none", result.stderr)
                        self.assertNotIn(CANARY, result.stdout + result.stderr)
            for payload in (line + "\n", one_line_tail):
                self.client_reply(stderr=payload)
                result = self.shell(self.startup_body())
                self.assertEqual(result.returncode, 0)
                self.assertIn(f" rootlesskit_self_reexec={expected} inspect_reported_apparmor=unknown\n", result.stderr)

    def test_startup_tail_and_failed_logs_status_keep_original_bounds_and_closed_fallback(self):
        self.client_reply("ERROR: storage driver failed\n" + "x" * 70000 + "\n")
        result = self.shell(self.startup_body())
        self.assertIn("category=unclassified families=none", result.stderr)
        self.client_reply("x" * 70000 + "\n", stderr="ERROR: storage driver failed " + CANARY + "\n")
        result = self.shell(self.startup_body())
        self.assertIn("category=daemon_storage families=daemon_storage", result.stderr)
        self.assertNotIn(CANARY, result.stdout + result.stderr)
        self.client_reply(stderr="newuidmap:" * 10000 + "\n")
        result = self.shell(self.startup_body())
        self.assertIn("category=unclassified families=none", result.stderr)
        for status in (1, 124):
            self.client_reply(stderr="ERROR: storage driver failed " + CANARY, status=status)
            result = self.shell(self.startup_body())
            self.assertEqual(result.returncode, 0)
            self.assertIn("stage=unavailable category=unavailable families=unavailable preflight=unavailable trace=unavailable", result.stderr)
            self.assertIn("rootlesskit_self_reexec=unavailable", result.stderr)
            self.assertNotIn(CANARY, result.stdout + result.stderr)

    def test_verified_fatal_preflight_messages_are_closed_observations_not_xtrace_or_echo(self):
        messages = (
            ("XDG_RUNTIME_DIR needs to be set and writable", "xdg", "daemon_startup"),
            ("HOME needs to be set and exist.", "home", "daemon_startup"),
            ("rootlesskit needs to be installed", "rootlesskit", "rootless_launcher_unavailable"),
            ("dockerd-rootless.sh conflicts with containerd-rootless.sh. Stop containerd-rootless.sh if it's running, "
             f"and remove /private/{CANARY} if it still exists.", "state", "daemon_startup"),
            ("This script must be executed as a non-privileged user", "uid", "daemon_startup"),
            (f"Unknown DOCKERD_ROOTLESS_ROOTLESSKIT_DETACH_NETNS value: {CANARY}", "detach", "daemon_startup"),
        )
        for message, preflight, family in messages:
            self.client_reply(CANARY + "\n", stderr=message + "\n")
            result = self.shell(self.startup_body())
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr,
                "inner daemon startup diagnosis: state=running=false,status=exited,exit=nonzero,oom=false,error=true "
                f"stage=daemon category={family} families={family} preflight={preflight} trace=unavailable "
                "rootlesskit_self_reexec=unobserved inspect_reported_apparmor=unknown\n")
            for prefix in ("echo ", "+ echo ", "++ echo "):
                self.client_reply(prefix + message + "\n")
                result = self.shell(self.startup_body())
                self.assertIn("category=unclassified families=none preflight=none", result.stderr)
                self.assertNotIn(CANARY, result.stdout + result.stderr)

    def test_preflight_order_retains_mixed_observations_without_interpreting_dynamic_values(self):
        self.client_reply("rootlesskit needs to be installed\nHOME needs to be set and exist.\n")
        result = self.shell(self.startup_body())
        self.assertIn("category=ambiguous families=rootless_launcher_unavailable,daemon_startup preflight=home,rootlesskit", result.stderr)
        self.client_reply(
            "Unknown DOCKERD_ROOTLESS_ROOTLESSKIT_DETACH_NETNS value: ERROR: iptables failed\n",
            stderr="dockerd-rootless.sh conflicts with containerd-rootless.sh. Stop containerd-rootless.sh if it's running, "
            f"and remove /private/ERROR: storage driver {CANARY} if it still exists.\n")
        result = self.shell(self.startup_body())
        self.assertIn("category=daemon_startup families=daemon_startup preflight=state,detach", result.stderr)
        self.assertNotIn(CANARY, result.stdout + result.stderr)
        self.assertNotIn("daemon_network", result.stderr)
        self.assertNotIn("daemon_storage", result.stderr)

    @staticmethod
    def group_driver():
        # Dedicated subreaper. Mutate only a held unreaped direct child or an
        # adopted child whose lifetime is independently proven by waitpid.
        return r'''
import ctypes,json,os,signal,subprocess,sys,time
from pathlib import Path
assert ctypes.CDLL(None).prctl(36,1,0,0,0)==0
mode,receipt,command=sys.argv[1:]
process=subprocess.Popen(json.loads(command),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
try:
 if mode=='cancel':
  until=time.monotonic()+3
  while not Path(receipt).exists() and time.monotonic()<until: time.sleep(0.005)
  assert Path(receipt).exists()
  os.kill(process.pid,signal.SIGTERM)
 output,error=process.communicate(timeout=13)
 code=process.returncode
finally:
 if process.poll() is None:
  process.kill();process.communicate()
pid=json.loads(Path(receipt).read_text())
late=False
until=time.monotonic()+0.75
while True:
 try: reaped,_=os.waitpid(pid,os.WNOHANG)
 except ChildProcessError: break
 if reaped==pid: break
 if time.monotonic()>=until:
  os.kill(pid,signal.SIGKILL);os.waitpid(pid,0);late=True;break
 time.sleep(0.005)
assert not late
print(json.dumps({'status':code,'stdout':output,'stderr':error}))
'''

    def test_root_owned_ten_second_log_timer_stall_and_cancellation_reap_owned_client(self):
        # Projection above proves the diagnostic uses this exact root-owned
        # command vector; execute its timer directly so cancellation never uses
        # a recovered PID. The sudo executable is an authored unprivileged fake.
        self.startup_body(True)
        receipt = self.private / "pids"
        self.tool(self.client, "import os,json,time\nfrom pathlib import Path\n"
                  "receipt=Path(os.environ['PIDS'])\n"
                  "pending=receipt.with_suffix('.pending')\n"
                  "pending.write_text(json.dumps(os.getpid()));pending.rename(receipt)\n"
                  "time.sleep(60)\n")
        command = [str(self.tools / "sudo"), "-n", "timeout", "--signal=TERM", "--kill-after=2s", "10s",
                   str(self.client), "--config", "/held/config", "--host", "unix:///held/socket",
                   "logs", "--tail", "80", "exact-owned-name"]
        # Popen exposes a directly signalled child's status as negative SIGTERM;
        # the Bash harness would project the same signal as 128 + SIGTERM.
        for mode, expected in (("stall", 124), ("cancel", -signal.SIGTERM)):
            receipt.unlink(missing_ok=True)
            started = time.monotonic()
            result = subprocess.run([sys.executable, "-c", self.group_driver(), mode,
                                     str(receipt), json.dumps(command)],
                                    env=self.env | {"PIDS": str(receipt), "SUDO_TRACE": str(self.private / "sudo-trace")},
                                    capture_output=True, text=True, timeout=16)
            self.assertEqual(result.returncode, 0, "closed owned-group control failed")
            self.assertEqual(json.loads(result.stdout), {"status": expected, "stdout": "", "stderr": ""})
            self.assertLess(time.monotonic() - started, 13)
            if mode == "stall":
                self.assertGreaterEqual(time.monotonic() - started, 9)

    def test_merged_stderr_collector_stall_keeps_original_timer_and_closed_unavailable_status(self):
        body = self.startup_body(True)
        receipt = self.private / "pids"
        self.tool(self.client, "import os,json,sys,time\nfrom pathlib import Path\n"
                  f"sys.stderr.write('x'*100000+'\\nERROR: storage driver failed {CANARY}\\n');sys.stderr.flush()\n"
                  "receipt=Path(os.environ['PIDS']);pending=receipt.with_suffix('.pending')\n"
                  "pending.write_text(json.dumps(os.getpid()));pending.rename(receipt)\n"
                  "time.sleep(60)\n")
        started = time.monotonic()
        result = subprocess.run([sys.executable, "-c", self.group_driver(), "stall",
                                 str(receipt), json.dumps(["/bin/bash", "-c", body])],
                                env=self.env | {"PIDS": str(receipt), "SUDO_TRACE": str(self.private / "sudo-trace")},
                                capture_output=True, text=True, timeout=16)
        self.assertEqual(result.returncode, 0, "closed owned collector-stall control failed")
        observation = json.loads(result.stdout)
        self.assertEqual(observation["status"], 0)
        self.assertEqual(observation["stdout"], "")
        self.assertEqual(observation["stderr"],
            "inner daemon startup diagnosis: state=running=false,status=exited,exit=nonzero,oom=false,error=true "
            "stage=unavailable category=unavailable families=unavailable preflight=unavailable trace=unavailable "
            "rootlesskit_self_reexec=unavailable inspect_reported_apparmor=unknown\n")
        self.assertGreaterEqual(time.monotonic() - started, 9)
        self.assertLess(time.monotonic() - started, 13)

    def test_wget_sanitizer_accepts_only_closed_whole_line_categories(self):
        cargo = self.tools / "cargo"
        for category in ("connection_refused", "no_route", "timeout", "http_error", "unknown"):
            self.tool(cargo, "import sys\n"
                      "if '--list' in sys.argv:\n"
                      " print('native_network_tests::live_internal_network_blocks_external_egress: test')\n"
                      "else:\n"
                      f" print('DOCKERLENS_NATIVE_WGET_DIAG: category={category}')\n"
                      f" print('DOCKERLENS_NATIVE_WGET_DIAG: category={CANARY}')\n"
                      " print('DOCKERLENS_NATIVE_WGET_DIAG: category=timeout private-canary')\n"
                      " print('test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;')\n"
                      " raise SystemExit(101)\n")
            result = subprocess.run(["/bin/bash", str(ROOT / "scripts/run-exact-native-test.sh"),
                                     "native_network", "live_internal_network_blocks_external_egress"],
                                    env=self.env, capture_output=True, text=True, timeout=4)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(f"DOCKERLENS_NATIVE_WGET_DIAG: category={category}\n", result.stderr)
            self.assertNotIn("private-canary", result.stdout + result.stderr)

    def test_subnet_pair_sanitizer_keeps_each_closed_observation_and_failure_only_output(self):
        cargo = self.tools / "cargo"
        for internal, control in (("true", "false"), ("false", "true"), ("unknown", "true"),
                                  ("true", "unknown"), (None, "false"), ("false", None),
                                  (CANARY, "true"), ("true", CANARY)):
            for success in (False, True):
                lines = []
                for label, value in (("INTERNAL", internal), ("CONTROL", control)):
                    if value is not None:
                        lines.append(f"DOCKERLENS_NATIVE_{label}_SUBNET_DIAG: sidecar_on_{label.lower()}_subnet={value}")
                    lines.append(f"DOCKERLENS_NATIVE_{label}_SUBNET_DIAG: sidecar_on_{label.lower()}_subnet=false private-canary")
                lines.append("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;" if success
                             else "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;")
                self.tool(cargo, "import sys\n"
                          "if '--list' in sys.argv:\n"
                          " print('native_network_tests::live_internal_network_blocks_external_egress: test')\n"
                          f"else:\n print({chr(10).join(lines)!r})\n raise SystemExit({0 if success else 101})\n")
                result = subprocess.run(["/bin/bash", str(ROOT / "scripts/run-exact-native-test.sh"),
                                         "native_network", "live_internal_network_blocks_external_egress"],
                                        env=self.env, capture_output=True, text=True, timeout=4)
                self.assertEqual(result.returncode == 0, success)
                for label, value in (("INTERNAL", internal), ("CONTROL", control)):
                    marker = f"DOCKERLENS_NATIVE_{label}_SUBNET_DIAG: sidecar_on_{label.lower()}_subnet="
                    if not success and value in ("true", "false", "unknown"):
                        self.assertIn(marker + value + "\n", result.stderr)
                    else:
                        self.assertNotIn(marker, result.stderr)
                self.assertNotIn("private-canary", result.stdout + result.stderr)
                self.assertNotIn(CANARY, result.stdout + result.stderr)

    def test_control_subnet_sanitizer_projects_only_closed_target_membership(self):
        cargo = self.tools / "cargo"
        for membership in ("true", "false", "unknown"):
            self.tool(cargo, "import sys\n"
                      "if '--list' in sys.argv:\n"
                      " print('native_network_tests::live_internal_network_blocks_external_egress: test')\n"
                      "else:\n"
                      f" print('DOCKERLENS_NATIVE_CONTROL_SUBNET_DIAG: sidecar_on_control_subnet={membership}')\n"
                      f" print('DOCKERLENS_NATIVE_CONTROL_SUBNET_DIAG: sidecar_on_control_subnet={CANARY}')\n"
                      " print('DOCKERLENS_NATIVE_CONTROL_SUBNET_DIAG: sidecar_on_control_subnet=true private-canary')\n"
                      " print('test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;')\n"
                      " raise SystemExit(101)\n")
            result = subprocess.run(["/bin/bash", str(ROOT / "scripts/run-exact-native-test.sh"),
                                     "native_network", "live_internal_network_blocks_external_egress"],
                                    env=self.env, capture_output=True, text=True, timeout=4)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(f"DOCKERLENS_NATIVE_CONTROL_SUBNET_DIAG: sidecar_on_control_subnet={membership}\n", result.stderr)
            self.assertNotIn("private-canary", result.stdout + result.stderr)
            self.assertNotIn("10.89.0.2", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
