"""Hermetic diagnostic-only controls: no runtime binary can be resolved."""
import json
import os
from pathlib import Path
import shlex
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
GUEST_HTTP_SCRIPT = r'''
LC_ALL=C LANG=C
export LC_ALL LANG
if [ ! -e /usr/bin/curl ]; then
  printf "DLHTTP1|absent||-\n"
elif [ ! -x /usr/bin/curl ]; then
  printf "DLHTTP1|not_executable||-\n"
else
  printf "DLHTTP1|executable|"
  /usr/bin/curl --disable -sS --noproxy "*" --retry 0 --proto "=http" \
    --max-time 2 --request GET --output /dev/null --write-out "%{http_code}" "$1"
  curl_status=$?
  case $curl_status in 130 | 143) exit "$curl_status" ;; esac
  printf "|%s\n" "$curl_status"
fi
'''
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

    def guest_client_reply(self, stdout="200", status=0, stderr="", *, curl_status=0):
        self.client_reply(f"DLHTTP1|executable|{stdout}|{curl_status}\n", status, stderr)

    @staticmethod
    def guest_observation(status="unavailable", *, tool="unavailable", callable_status="unavailable",
                          curl_exit="unavailable", reports=None):
        result = (f"DOCKERLENS_NATIVE_OUTER_GUEST_HTTP: status={status}\n"
                  f"DOCKERLENS_NATIVE_OUTER_GUEST_CURL: tool={tool} callable={callable_status} curl_exit={curl_exit}\n")
        if reports is None:
            if tool == "unavailable":
                return result
            reports = ("unavailable",) * 3
        return (result + "DOCKERLENS_NATIVE_PRE_TEST_NETWORK_REPORT: source=captured_inner_engine_info "
                f"IPv4Forwarding={reports[0]} BridgeNfIptables={reports[1]} BridgeNfIp6tables={reports[2]}\n")

    @staticmethod
    def guest_argv():
        return ["exec", "a" * 64, "/bin/sh", "-c", GUEST_HTTP_SCRIPT,
                "dockerlens-guest-http", "http://10.23.7.9:18084/"]

    def guest_http_body(self, *, privileged=False, remaining=9, watchdog=True, invoke=True, info_dir=None):
        vector = [str(self.client)]
        if privileged:
            self.tool(self.tools / "sudo", "import os,sys\n"
                      "assert sys.argv[1]=='-n'\nos.execvp(sys.argv[2],sys.argv[2:])\n")
            vector = ["sudo", "-n", *vector]
        body = ("set -euo pipefail\n" + definition("native_outer_command", RUNTIME)
                + definition("outer_guest_http_failure_diagnostic")
                + "native_outer_cmd=(" + " ".join(repr(item) for item in vector) + ")\n"
                + "native_outer_engine=docker\nexpected_mode=rootless\nmain_pid=$$\n"
                + ("watchdog_pid=$$\n" if watchdog else "watchdog_pid=\n")
                + "outer_container_id=" + "a" * 64 + "\nsidecar_ip=10.23.7.9\n"
                # Unset Bash's ticking special variable before assigning the
                # ordinary fixed fixture clock; startup cannot spend its budget.
                + "unset SECONDS\n"
                + f"SECONDS={1800 - remaining}\n"
                + "trap 'exit 130' INT\ntrap 'exit 143' TERM\n")
        if info_dir is not None:
            body += f"run_dir={shlex.quote(str(info_dir))}\n"
        if invoke:
            body += "outer_guest_http_failure_diagnostic || true\nexit 17\n"
        return body

    def info_fixture(self, raw=b"{}", mode=0o600):
        directory = self.private / "captured-info"
        directory.mkdir(mode=0o700, exist_ok=True)
        path = directory / "info.json"
        path.write_bytes(raw)
        path.chmod(mode)
        return directory

    def assert_info_observation(self, directory, reports=("unavailable",) * 3):
        self.guest_client_reply("200", stderr=CANARY)
        result = self.shell(self.guest_http_body(info_dir=directory))
        self.assertEqual((result.returncode, result.stdout), (17, ""))
        self.assertEqual(result.stderr, self.guest_observation("http_200", tool="executable",
                         callable_status="yes", curl_exit="success", reports=reports))
        self.assertEqual(json.loads(self.trace.read_text()), self.guest_argv())
        self.assertNotIn(CANARY, result.stdout + result.stderr)
        self.assertNotIn(str(directory), result.stdout + result.stderr)

    def test_captured_info_closed_reports_preserve_both_original_http_lines(self):
        for mode in (0o600, 0o644):
            for value, reports in (
                ({"IPv4Forwarding": True, "BridgeNfIptables": False, "BridgeNfIp6tables": True,
                  "protected": CANARY}, ("reported_true", "reported_false", "reported_true")),
                ({"IPv4Forwarding": False, "BridgeNfIptables": True, "BridgeNfIp6tables": False},
                 ("reported_false", "reported_true", "reported_false")),
                ({"IPv4Forwarding": None, "BridgeNfIptables": False},
                 ("unavailable", "reported_false", "unavailable")),
                ({}, ("unavailable",) * 3),
            ):
                with self.subTest(mode=mode, reports=reports):
                    self.assert_info_observation(self.info_fixture(json.dumps(value).encode(), mode), reports)

    def test_bad_info_types_json_and_bounds_are_unavailable_without_losing_http(self):
        raw_cases = [b"", b"{", b"[]", b"null", b"true", b"42", b"\xff",
                     b'{"IPv4Forwarding":true,"IPv4Forwarding":false}',
                     b'{"IPv4Forwarding":true,"ignored":{"x":1,"x":2}}',
                     b'{"IPv4Forwarding":true,"ignored":NaN}',
                     b'{"IPv4Forwarding":true,"ignored":[Infinity]}',
                     b'{"IPv4Forwarding":true,"ignored":{"x":1e999}}',
                     b'{"IPv4Forwarding":true,"ignored":' + b"[" * 33 + b"0" + b"]" * 33 + b"}",
                     b'{"IPv4Forwarding":true,"protected":"' + CANARY.encode() + b'"}' + b" " * 65536]
        for key in ("IPv4Forwarding", "BridgeNfIptables", "BridgeNfIp6tables"):
            for value in (0, 1, "false", "true", [], {}, 0.0):
                raw_cases.append(json.dumps({"IPv4Forwarding": True, key: value}).encode())
        for raw in raw_cases:
            with self.subTest(length=len(raw), prefix=raw[:48]):
                self.assert_info_observation(self.info_fixture(raw))
        raw = b'{"IPv4Forwarding":true}'
        directory = self.info_fixture(raw + b" " * (65536 - len(raw)), mode=0o644)
        self.assert_info_observation(directory, ("reported_true", "unavailable", "unavailable"))

    def test_info_private_directory_regular_single_link_and_modes_are_mandatory(self):
        directory = self.info_fixture(b'{"IPv4Forwarding":true}')
        path = directory / "info.json"
        path.unlink()
        self.assert_info_observation(directory)
        path.symlink_to(self.private / "missing-protected-canary")
        self.assert_info_observation(directory)
        path.unlink()
        os.mkfifo(path, 0o600)
        self.assert_info_observation(directory)
        path.unlink()
        path.mkdir(mode=0o700)
        self.assert_info_observation(directory)
        path.rmdir()
        path.write_bytes(b'{"IPv4Forwarding":true}')
        path.chmod(0o600)
        linked = self.private / "linked-info"
        os.link(path, linked)
        self.assert_info_observation(directory)
        linked.unlink()
        for mode in (0o620, 0o602, 0o666):
            path.chmod(mode)
            self.assert_info_observation(directory)
        path.chmod(0o600)
        directory.chmod(0o755)
        self.assert_info_observation(directory)
        directory.chmod(0o700)
        alias = self.private / "alias-info"
        alias.symlink_to(directory, target_is_directory=True)
        self.assert_info_observation(alias)

    def test_missing_curl_still_permits_complete_frame_pre_test_reports(self):
        directory = self.info_fixture(b'{"IPv4Forwarding":true,"BridgeNfIptables":false}')
        for tool in ("absent", "not_executable"):
            self.client_reply(f"DLHTTP1|{tool}||-\n", stderr=CANARY)
            result = self.shell(self.guest_http_body(info_dir=directory))
            self.assertEqual((result.returncode, result.stdout), (17, ""))
            self.assertEqual(result.stderr, self.guest_observation(tool=tool, callable_status="no",
                             curl_exit="not_called", reports=("reported_true", "reported_false", "unavailable")))
            self.assertEqual(json.loads(self.trace.read_text()), self.guest_argv())

    @staticmethod
    def guest_reader():
        return definition("outer_guest_http_failure_diagnostic").split("python3 -I -S -c '\n", 1)[1].split(
            "\n' \"${run_dir:-}\"", 1)[0]

    def test_info_fd_path_and_directory_stability_and_caller_ownership(self):
        for mutation in ("file-replace", "file-write", "file-mode", "parent-replace", "parent-mode",
                         "source-owner", "parent-owner"):
            with self.subTest(mutation=mutation):
                directory = self.private / mutation
                directory.mkdir(mode=0o700)
                path = directory / "info.json"
                path.write_bytes(b'{"IPv4Forwarding":true}')
                path.chmod(0o600)
                # Deterministic synthetic race at the actual held-file read,
                # never a concurrent writer or host ownership change.
                prelude = ("import os,stat,sys\nfrom pathlib import Path\n"
                           "original_read=os.read\noriginal_stat=os.fstat\nmutated=False\n"
                           f"mutation={mutation!r}\n"
                           "def changed_read(fd,count):\n"
                           " global mutated\n value=original_read(fd,count)\n"
                           " if fd != 0 and not mutated:\n"
                           "  mutated=True\n  parent=Path(sys.argv[1]);path=parent/'info.json'\n"
                           "  if mutation=='file-replace':\n"
                           "   path.unlink();path.write_bytes(value);path.chmod(0o600)\n"
                           "  elif mutation=='file-write': path.write_bytes(b' '*len(value))\n"
                           "  elif mutation=='file-mode': path.chmod(0o644)\n"
                           "  elif mutation=='parent-mode': parent.chmod(0o755)\n"
                           "  elif mutation=='parent-replace':\n"
                           "   parent.rename(parent.with_suffix('.held'));parent.mkdir(mode=0o700)\n"
                           " return value\n"
                           "def changed_stat(fd):\n"
                           " value=original_stat(fd)\n"
                           " if ((mutation=='source-owner' and stat.S_ISREG(value.st_mode)) or\n"
                           "     (mutation=='parent-owner' and stat.S_ISDIR(value.st_mode))):\n"
                           "  fields=list(value);fields[4]=os.geteuid()+1;return os.stat_result(fields)\n"
                           " return value\n"
                           "os.read=changed_read\nos.fstat=changed_stat\n")
                result = subprocess.run([sys.executable, "-I", "-S", "-c", prelude + self.guest_reader(), str(directory)],
                                        input="DLHTTP1|executable|200|0\n", text=True, capture_output=True, timeout=3)
                self.assertEqual((result.returncode, result.stderr), (0, ""))
                self.assertEqual(result.stdout, "http_200 tool=executable callable=yes curl_exit=success "
                                 "DLINFO1|unavailable|unavailable|unavailable\n")
                self.assertNotIn(CANARY, result.stdout + result.stderr)

    def test_true_info_cannot_bypass_pipeline_cancellation_deadline_or_watchdog(self):
        directory = self.info_fixture(b'{"IPv4Forwarding":true,"BridgeNfIptables":true,"BridgeNfIp6tables":true}')
        for status in (1, 124, 125, 126, 127, 137, 130, 143):
            self.guest_client_reply("200", status)
            result = self.shell(self.guest_http_body(info_dir=directory))
            cancelled = status in (130, 143)
            self.assertEqual((result.returncode, result.stdout), (status if cancelled else 17, ""))
            self.assertEqual(result.stderr, "" if cancelled else self.guest_observation())
        self.guest_client_reply("200")
        for options in ({"remaining": 8}, {"watchdog": False}):
            self.trace.unlink(missing_ok=True)
            result = self.shell(self.guest_http_body(info_dir=directory, **options))
            self.assertEqual((result.returncode, result.stderr), (17, self.guest_observation()))
            self.assertFalse(self.trace.exists())
        body = self.guest_http_body(info_dir=directory, invoke=False)
        body += ("read() { case $2 in started) printf -v started %s 100.00 ;; "
                 "ended) printf -v ended %s 107.99 ;; esac; }\n"
                 "outer_guest_http_failure_diagnostic || true\nexit 17\n")
        result = self.shell(body)
        self.assertEqual((result.returncode, result.stderr), (17, self.guest_observation()))

    def test_reader_status_and_closed_suffix_are_checked_before_any_emission(self):
        directory = self.info_fixture(b'{"IPv4Forwarding":true}')
        valid = "http_200 tool=executable callable=yes curl_exit=success DLINFO1|true|true|true\n"
        cases = [(code, valid) for code in (1, 124, 137, 130, 143)]
        cases += [(0, raw) for raw in (valid.replace("|true\n", "|1\n"), valid + valid,
                                      valid + CANARY, valid.replace("DLINFO1", "DLINFO2"))]
        (self.tools / "timeout").unlink()
        for code, raw in cases:
            with self.subTest(code=code, raw=raw[:80]):
                self.guest_client_reply("200")
                self.tool(self.tools / "timeout", "import os,sys\n"
                          "if sys.argv[1:5] == ['--signal=TERM','--kill-after=1s','6s','python3']:\n"
                          " sys.stdin.buffer.read(65)\n"
                          f" sys.stdout.write({raw!r});raise SystemExit({code})\n"
                          "os.execv('/usr/bin/timeout',['timeout',*sys.argv[1:]])\n")
                result = self.shell(self.guest_http_body(info_dir=directory))
                cancelled = code in (130, 143)
                self.assertEqual((result.returncode, result.stdout), (code if cancelled else 17, ""))
                self.assertEqual(result.stderr, "" if cancelled else self.guest_observation())
                self.assertNotIn(CANARY, result.stdout + result.stderr)

    def test_existing_reader_owner_kills_stalled_info_without_http_success(self):
        directory = self.info_fixture(b'{"IPv4Forwarding":true}')
        self.guest_client_reply("200")
        body = self.guest_http_body(info_dir=directory)
        body = body.replace("import json\nimport math\n", "import signal,time\n"
                            "signal.signal(signal.SIGTERM,signal.SIG_IGN)\nimport json\nimport math\n")
        body = body.replace("part = os.read(source, 65537 - len(captured))",
                            "time.sleep(60)\n            part = os.read(source, 65537 - len(captured))")
        started = time.monotonic()
        result = self.shell(body, timeout=10)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (17, "", self.guest_observation()))
        self.assertGreaterEqual(time.monotonic() - started, 6.5)
        self.assertLess(time.monotonic() - started, 9)

    def test_guest_http_status_only_fixed_direct_client_and_unavailable_inputs(self):
        expected = self.guest_argv()
        for stdout, status, result_status in (
            ("200", 0, "http_200"), ("201", 0, "http_other"), ("404", 0, "http_other"),
            ("599", 0, "http_other"), ("", 127, "unavailable"), ("200", 7, "unavailable"),
            ("200", 124, "unavailable"), ("000", 0, "unavailable"), ("600", 0, "unavailable"),
            ("200\n", 0, "unavailable"), ("200200", 0, "unavailable"), (CANARY, 0, "unavailable"),
            ("200x", 0, "unavailable"), ("2" * 100000, 0, "unavailable"),
        ):
            with self.subTest(status=status, output_class=result_status):
                self.guest_client_reply(stdout, status, CANARY)
                result = self.shell(self.guest_http_body(privileged=True), timeout=9)
                self.assertEqual(result.returncode, 17)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, self.guest_observation(result_status, **(
                    {"tool": "executable", "callable_status": "yes", "curl_exit": "success"}
                    if result_status != "unavailable" else {})))
                self.assertEqual(json.loads(self.trace.read_text()), expected)
                self.assertNotIn(CANARY, result.stdout + result.stderr)

    def test_guest_http_late_budget_missing_watchdog_and_boottime_refuse_positive(self):
        self.guest_client_reply("200")
        for body in (self.guest_http_body(remaining=8), self.guest_http_body(watchdog=False)):
            self.trace.unlink(missing_ok=True)
            result = self.shell(body)
            self.assertEqual(result.returncode, 17)
            self.assertEqual(result.stderr, self.guest_observation())
            self.assertFalse(self.trace.exists())
        for body in (self.guest_http_body().replace("expected_mode=rootless", "expected_mode=rootful"),
                     self.guest_http_body().replace("native_outer_engine=docker", "native_outer_engine=podman")):
            self.trace.unlink(missing_ok=True)
            result = self.shell(body)
            self.assertEqual((result.returncode, result.stderr), (17, ""))
            self.assertFalse(self.trace.exists())
        for ended in ("107.98", "107.99", "99.99"):
            body = self.guest_http_body(invoke=False)
            body += ("read() { case $2 in started) printf -v started '%s' 100.00 ;; "
                     f"ended) printf -v ended '%s' {ended} ;; esac; }}\n"
                     "outer_guest_http_failure_diagnostic || true\nexit 17\n")
            result = self.shell(body)
            self.assertEqual(result.returncode, 17)
            expected = "http_200" if ended == "107.98" else "unavailable"
            self.assertEqual(result.stderr, self.guest_observation(expected, **(
                {"tool": "executable", "callable_status": "yes", "curl_exit": "success"}
                if expected == "http_200" else {})))

    def test_guest_http_fixed_shell_tool_availability_and_closed_curl_exits(self):
        curl = self.private / "fake-curl"
        calls = self.private / "curl-calls"
        expected_options = ["--disable", "-sS", "--noproxy", "*", "--retry", "0", "--proto", "=http",
                            "--max-time", "2", "--request", "GET", "--output", "/dev/null",
                            "--write-out", "%{http_code}", "http://10.23.7.9:18084/"]
        self.tool(self.client, "import json,os,sys\nfrom pathlib import Path\n"
                  f"assert sys.argv[1:] == {self.guest_argv()!r}\n"
                  "Path(os.environ['TRACE']).write_text(json.dumps(sys.argv[1:]))\n"
                  f"script=sys.argv[5].replace('/usr/bin/curl', {str(curl)!r})\n"
                  "os.execv('/bin/sh', ['/bin/sh', '-c', script, sys.argv[6], sys.argv[7]])\n")
        cases = (
            ("absent", "", 0, "unavailable", "absent", "no", "not_called"),
            ("not_executable", "", 0, "unavailable", "not_executable", "no", "not_called"),
            ("missing_loader", "", 0, "unavailable", "executable", "no", "unavailable"),
            ("executable", "", 126, "unavailable", "executable", "no", "unavailable"),
            ("executable", "200", 0, "http_200", "executable", "yes", "success"),
            ("executable", "404", 0, "http_other", "executable", "yes", "success"),
            *(("executable", "200", code, "unavailable", "executable", "yes", category)
              for code, category in ((5, "resolve_proxy"), (6, "resolve_host"), (7, "connect_failed"),
                                     (28, "timeout"), (52, "empty_reply"), (55, "send_failed"),
                                     (56, "receive_failed"), (1, "other"), (99, "other"))),
        )
        for fixture, stdout, code, status, tool, callable_status, category in cases:
            with self.subTest(fixture=fixture, curl_exit=code):
                curl.unlink(missing_ok=True)
                calls.unlink(missing_ok=True)
                if fixture != "absent":
                    self.tool(curl, "import json,os,sys\nfrom pathlib import Path\n"
                              "assert os.environ['LC_ALL'] == os.environ['LANG'] == 'C'\n"
                              f"with Path({str(calls)!r}).open('a') as calls:\n"
                              " calls.write(json.dumps(sys.argv[1:])+'\\n')\n"
                              f"sys.stdout.write({stdout!r});sys.stdout.flush()\n"
                              f"sys.stderr.write({CANARY!r});raise SystemExit({code})\n")
                    if fixture == "not_executable":
                        curl.chmod(0o600)
                    elif fixture == "missing_loader":
                        curl.write_text("#!/nonexistent/dockerlens-fake-loader\n")
                result = self.shell(self.guest_http_body(privileged=True), timeout=9)
                self.assertEqual(result.returncode, 17)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, self.guest_observation(status, tool=tool,
                                 callable_status=callable_status, curl_exit=category))
                self.assertEqual(json.loads(self.trace.read_text()), self.guest_argv())
                self.assertEqual(calls.exists(), fixture == "executable")
                if calls.exists():
                    self.assertEqual([json.loads(line) for line in calls.read_text().splitlines()],
                                     [expected_options])
                self.assertNotIn(CANARY, result.stdout + result.stderr)
        # A curl cancellation exits the fixed shell before a trailer is emitted.
        for code in (130, 143):
            self.tool(curl, f"raise SystemExit({code})\n")
            result = self.shell(self.guest_http_body())
            self.assertEqual((result.returncode, result.stdout, result.stderr), (code, "", ""))

    def test_guest_http_complete_bounded_frame_is_required_for_all_facts(self):
        valid = "DLHTTP1|executable|200|0\n"
        malformed = (
            "", "200", "DLHTTP1|executable|", valid[:-1], valid + "\n", valid + valid,
            "prefix" + valid, valid + "suffix", "DLHTTP1|executable|200|0\nprotected-canary",
            "DLHTTP1|executable|200|00\n", "DLHTTP1|executable|200|+0\n",
            "DLHTTP1|executable|200|-1\n", "DLHTTP1|executable|200|128\n",
            "DLHTTP1|executable|200|256\n", "DLHTTP1|executable|200|9999\n",
            "DLHTTP1|executable|099|7\n", "DLHTTP1|executable|600|7\n",
            "DLHTTP1|executable|20|7\n", "DLHTTP1|executable|200|127\n",
            "DLHTTP1|executable||-\n", "DLHTTP1|absent|200|-\n",
            "DLHTTP1|absent||0\n", "DLHTTP1|not_executable||127\n",
            "DLHTTP1|other||-\n", "DLHTTP1|executable|000|0\n",
            valid.replace("\n", "\r\n"), valid + "x" * 100000,
        )
        for raw in malformed:
            with self.subTest(length=len(raw), prefix=raw[:32]):
                self.client_reply(raw, stderr=CANARY)
                result = self.shell(self.guest_http_body())
                self.assertEqual((result.returncode, result.stdout), (17, ""))
                self.assertEqual(result.stderr, self.guest_observation())
                self.assertNotIn(CANARY, result.stdout + result.stderr)
        # Valid bytes are not facts unless the original owner also completes.
        for code in (1, 124, 125, 126, 127, 137):
            self.client_reply(valid, code)
            result = self.shell(self.guest_http_body())
            self.assertEqual(result.returncode, 17)
            self.assertEqual(result.stderr, self.guest_observation())
        for code in (130, 143):
            self.client_reply("invalid partial frame", code)
            result = self.shell(self.guest_http_body())
            self.assertEqual((result.returncode, result.stdout, result.stderr), (code, "", ""))

    def test_guest_http_original_native_status_and_cancellation_skip_contact(self):
        start = SOURCE.index("internal_network_status=0\n")
        end = SOURCE.index('"$(dirname "$0")/run-exact-native-test.sh" native_volume ', start)
        wrapper = SOURCE[start:end]
        fake_native = self.private / "fake-native-test"
        self.guest_client_reply("200")
        for native_status in (0, 17, 130, 143):
            self.trace.unlink(missing_ok=True)
            self.tool(fake_native, f"raise SystemExit({native_status})\n")
            body = self.guest_http_body(invoke=False)
            body += wrapper.replace('"$(dirname "$0")/run-exact-native-test.sh"', repr(str(fake_native)))
            body += "exit 0\n"
            result = self.shell(body)
            self.assertEqual(result.returncode, native_status)
            self.assertEqual(self.trace.exists(), native_status == 17)
            self.assertEqual(result.stderr,
                             self.guest_observation("http_200", tool="executable", callable_status="yes",
                                                    curl_exit="success") if native_status == 17 else "")
        # Explicit child cancellation exits through the existing cleanup owner.
        for status in (130, 143):
            self.guest_client_reply("200", status)
            result = self.shell(self.guest_http_body())
            self.assertEqual(result.returncode, status)
            self.assertNotIn("status=http_200", result.stderr)

    def test_guest_http_fixed_fixture_clock_survives_delayed_native_failure(self):
        start = SOURCE.index("internal_network_status=0\n")
        end = SOURCE.index('"$(dirname "$0")/run-exact-native-test.sh" native_volume ', start)
        wrapper = SOURCE[start:end]
        fake_native = self.private / "delayed-fake-native-test"
        # A real elapsed second exhausted the former special SECONDS clock's
        # nine-second admission boundary before the fake client could be called.
        self.tool(fake_native, "import time\ntime.sleep(1.1)\nraise SystemExit(17)\n")
        self.guest_client_reply("200")
        body = self.guest_http_body(invoke=False)
        body += wrapper.replace('"$(dirname "$0")/run-exact-native-test.sh"', repr(str(fake_native)))
        body += "exit 0\n"
        result = self.shell(body)
        self.assertEqual(result.returncode, 17)
        self.assertEqual(result.stdout, "")
        self.assertTrue(self.trace.exists())
        self.assertEqual(result.stderr, self.guest_observation("http_200", tool="executable",
                                                             callable_status="yes", curl_exit="success"))

    def test_guest_http_child_cancellation_exits_cleanup_with_inherited_ignored_sigint(self):
        receipt = self.private / "guest-http-cleanup-status"
        for status in (130, 143):
            receipt.unlink(missing_ok=True)
            self.guest_client_reply("200", status)
            body = self.guest_http_body(invoke=False)
            body += ("trap 'cleanup_status=$?; printf \"%s\\n\" \"$cleanup_status\" > \"$CLEANUP_RECEIPT\"' EXIT\n"
                     "outer_guest_http_failure_diagnostic || true\n"
                     "printf 'unexpected-resume\\n' >&2\nexit 17\n")
            # An asynchronous Bash gate passes ignored SIGINT across exec.
            # The inner trap cannot restore it; cancellation must not rely on
            # delivering INT to self or a return swallowed by the || caller.
            result = subprocess.run(["/bin/bash", "-c", "trap '' INT; exec /bin/bash -c \"$1\"",
                                     "ignored-int-driver", body],
                                    env=self.env | {"CLEANUP_RECEIPT": str(receipt)},
                                    capture_output=True, text=True, timeout=4)
            self.assertEqual(result.returncode, status)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr, "")
            self.assertEqual(receipt.read_text(), f"{status}\n")
            self.assertNotIn("status=http_200", result.stderr)
            self.assertNotIn("unexpected-resume", result.stderr)

    def test_guest_http_direct_term_resistant_client_has_finite_eof_and_cancellation(self):
        receipt = self.private / "guest-client-pid"
        group = self.private / "guest-client-group"
        self.tool(self.client, "import json,os,signal,sys,time\nfrom pathlib import Path\n"
                  "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
                  "receipt=Path(os.environ['PIDS']);pending=receipt.with_suffix('.pending')\n"
                  "pending.write_text(json.dumps(os.getpid()));pending.rename(receipt)\n"
                  "Path(os.environ['PGROUP']).write_text(str(os.getpgrp()))\n"
                  "sys.stdout.write('DLHTTP1|executable|200|0\\n');sys.stdout.flush()\ntime.sleep(60)\n")
        for mode, expected in (("stall", 17), ("cancel", 143)):
            receipt.unlink(missing_ok=True)
            started = time.monotonic()
            result = subprocess.run([sys.executable, "-c", self.group_driver(), mode,
                                     str(receipt), json.dumps(["/bin/bash", "-c", self.guest_http_body(privileged=True)])],
                                    env=self.env | {"PIDS": str(receipt), "PGROUP": str(group)},
                                    capture_output=True, text=True, timeout=11)
            self.assertEqual(result.returncode, 0, "closed direct-client lifetime control failed")
            observation = json.loads(result.stdout)
            self.assertEqual(observation["status"], expected)
            self.assertNotIn("status=http_200", observation["stderr"])
            self.assertNotIn("tool=executable", observation["stderr"])
            if mode == "stall":
                self.assertEqual(observation["stderr"], self.guest_observation())
            self.assertLess(time.monotonic() - started, 8)
            self.assertGreaterEqual(time.monotonic() - started, 4.5)
            with self.assertRaises(ProcessLookupError):
                os.killpg(int(group.read_text()), 0)
        # Cancellation before the observation starts never launches the client.
        self.trace.unlink(missing_ok=True)
        receipt.unlink(missing_ok=True)
        body = self.guest_http_body(invoke=False) + 'kill -TERM "$main_pid"\nouter_guest_http_failure_diagnostic\n'
        result = self.shell(body)
        self.assertEqual(result.returncode, 143)
        self.assertFalse(self.trace.exists())
        self.assertFalse(receipt.exists())

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
                    + definition("rootless_kernel_window_diagnostic")
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
                + definition("rootless_kernel_window_diagnostic")
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
