"""Literal component controls only; never execute BOOTSTRAP or inspect /proc."""

from copy import deepcopy
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import re
import subprocess
import unittest

from native_outer_bootstrap import BOOTSTRAP, BootstrapError, build_bootstrap_argv, parse_bootstrap_log

NONCE = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CANARY = "PRIVATE_BOOTSTRAP_CANARY_/host/native/secret"
STAMP = b"2026-10-19T12:34:56.123456789Z"
# Authored independently of the implementation and json.dumps: decoder success
# cannot be explained by a shared producer or validator serialization mistake.
PAYLOAD = (b'{"contract":"outer-bootstrap-v1",'
           b'"nonce":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",'
           b'"pid":1,"proc_pid":1,"nspid":[1],"start":123456,"uid":0,'
           b'"namespaces":[4026533001,4026533002,4026533003],"membership":"0::/",'
           b'"mount":[101,99,"0:28","/","/sys/fs/cgroup"],'
           b'"controller":[28,2,512,4294967296]}')
FRAME = STAMP + b" stdout F DOCKERLENS_OUTER_BOOTSTRAP_V1 " + PAYLOAD + b"\n"
EXPECTED = {"contract": "outer-bootstrap-v1", "nonce": NONCE, "pid": 1, "proc_pid": 1,
            "nspid": [1], "start": 123456, "uid": 0,
            "namespaces": [4026533001, 4026533002, 4026533003], "membership": "0::/",
            "mount": [101, 99, "0:28", "/", "/sys/fs/cgroup"], "controller": [28, 2, 512, 4294967296]}


def frame(value):
    return STAMP + b" stdout F DOCKERLENS_OUTER_BOOTSTRAP_V1 " + json.dumps(value, separators=(",", ":")).encode("ascii") + b"\n"


class OuterBootstrapTests(unittest.TestCase):
    def refused(self, raw, nonce=NONCE):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            with self.assertRaises(BootstrapError) as caught:
                parse_bootstrap_log(raw, nonce)
        self.assertEqual(str(caught.exception), "outer bootstrap input refused")
        self.assertEqual(repr(caught.exception), "BootstrapError('outer bootstrap input refused')")
        self.assertNotIn(CANARY, repr(caught.exception))
        self.assertEqual(stdout.getvalue() + stderr.getvalue(), "")

    def test_literal_first_frame_exact_keys_tuples_and_no_origin_claim(self):
        result = parse_bootstrap_log(FRAME, NONCE)
        self.assertEqual(result, EXPECTED)
        self.assertEqual(set(result), {"contract", "nonce", "pid", "proc_pid", "nspid", "start", "uid",
                                       "namespaces", "membership", "mount", "controller"})
        self.assertEqual(result["mount"], [101, 99, "0:28", "/", "/sys/fs/cgroup"])
        self.assertEqual(result["controller"], [28, 2, 512, 4294967296])
        preceding = STAMP + b" stderr F pre-launch diagnostic\n"
        following = STAMP + b" stdout F application log\n" + STAMP + b" stderr F application error\n"
        self.assertEqual(parse_bootstrap_log(preceding + FRAME + following, NONCE), EXPECTED)
        self.assertFalse({"trusted", "qualified", "compatible", "admission"} & set(result))

    def test_all_four_exact_argv_tails_preserve_external_user_cwd_environment(self):
        profiles = [
            ("debian11-rootful", "root", "/", ["/usr/local/bin/start-dockerd", "--host=unix:///dockerlens-native/docker.sock"]),
            ("debian11-rootless", "docker", "/home/docker", ["/usr/local/bin/start-dockerd", "--host=unix:///dockerlens-native/docker.sock", "--storage-driver=vfs"]),
            ("upstream-rootful", "root", "/", ["/usr/local/bin/start-dockerd", "--host=unix:///dockerlens-native/docker.sock"]),
            ("upstream-rootless", "docker", "/home/docker", ["/usr/local/bin/start-dockerd", "--host=unix:///dockerlens-native/docker.sock"]),
        ]
        for lane, user, cwd, original in profiles:
            with self.subTest(lane=lane):
                before = original[:]
                result = build_bootstrap_argv(NONCE, original)
                self.assertEqual(result[:5], ["/bin/sh", "-c", BOOTSTRAP, "dl-outer-bootstrap", NONCE])
                self.assertEqual(result[5:], before)
                self.assertEqual(original, before)
                self.assertEqual([item.encode() for item in result[5:]], [item.encode() for item in before])
                self.assertNotIn("--user", result)
                self.assertNotIn("--workdir", result)
                self.assertNotIn("HOME=", result)
                self.assertNotIn("cd " + cwd, BOOTSTRAP)
                self.assertNotIn("USER=" + user, BOOTSTRAP)
        injection = ["launcher", "$(touch /never-run)", "'; exit 0; #", "line\nnext", "雪"]
        self.assertEqual(build_bootstrap_argv(NONCE, injection)[5:], injection)
        self.assertNotIn("/never-run", BOOTSTRAP)

    def test_argv_types_nonce_nul_utf8_and_size_boundaries(self):
        invalid = [[], (), "launcher", [""], [None], [True], [1], ["a\0b"], ["\ud800"],
                   ["x"] * 17, ["x" * 4097], ["雪" * 1366]]
        for value in invalid:
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(BootstrapError):
                    build_bootstrap_argv(NONCE, value)
        self.assertEqual(len(build_bootstrap_argv(NONCE, ["x"] * 16)), 21)
        self.assertEqual(build_bootstrap_argv(NONCE, ["x" * 4096])[-1], "x" * 4096)
        self.assertEqual(build_bootstrap_argv(NONCE, ["雪" * 1365, "x"])[-1], "x")
        for nonce in (None, True, b"a" * 64, "A" * 64, "a" * 63, "a" * 65, "g" * 64, "a" * 63 + "\n"):
            with self.assertRaises(BootstrapError):
                build_bootstrap_argv(nonce, ["launcher"])
            self.refused(FRAME, nonce)

    def test_every_required_key_unknown_fields_and_closed_errors(self):
        for key in EXPECTED:
            value = deepcopy(EXPECTED)
            del value[key]
            self.refused(frame(value))
        value = deepcopy(EXPECTED)
        value[CANARY] = CANARY
        self.refused(frame(value))
        for raw in (b"null", b"[]", b"true", b'"' + CANARY.encode() + b'"', b"{}", b"NaN", b"Infinity"):
            self.refused(STAMP + b" stdout F DOCKERLENS_OUTER_BOOTSTRAP_V1 " + raw + b"\n")

    def test_all_scalar_types_and_integer_bounds(self):
        for key in ("pid", "proc_pid", "start", "uid"):
            invalid = [None, True, False, 1.0, "1", [], {}, -1, 1 << 64]
            invalid += [0, 2] if key in ("pid", "proc_pid") else ([0] if key == "start" else [1 << 32])
            for replacement in invalid:
                value = deepcopy(EXPECTED)
                value[key] = replacement
                self.refused(frame(value))
        for key in ("contract", "nonce", "membership"):
            for replacement in (None, True, 1, [], {}, CANARY):
                value = deepcopy(EXPECTED)
                value[key] = replacement
                self.refused(frame(value))
        maximum = deepcopy(EXPECTED)
        maximum.update(start=(1 << 64) - 1, uid=(1 << 32) - 1)
        self.assertEqual(parse_bootstrap_log(frame(maximum), NONCE)["uid"], (1 << 32) - 1)

    def test_nspid_namespace_mount_controller_tuple_types_and_bounds(self):
        invalids = {
            "nspid": [None, True, 1, {}, [], [True], [0], [2], [1, 1], ["1"]],
            "namespaces": [None, True, 1, {}, [], [1, 2], [1, 2, 3, 4], [1, 2, True], [0, 2, 3], [-1, 2, 3], [1 << 64, 2, 3]],
            "mount": [None, True, {}, [], [101, 99, "0:28", "/", "/sys/fs/cgroup", "extra"]],
            "controller": [None, True, {}, [], [28, 2, 512], [28, 2, 512, 4294967296, 0]],
        }
        for key, replacements in invalids.items():
            for replacement in replacements:
                value = deepcopy(EXPECTED)
                value[key] = replacement
                self.refused(frame(value))
        for slot in range(3):
            for replacement in (None, True, False, 1.0, "1", [], {}, 0, -1, 1 << 64):
                value = deepcopy(EXPECTED)
                value["namespaces"][slot] = replacement
                self.refused(frame(value))
        for key, slots in (("mount", range(2)), ("controller", range(4))):
            for slot in slots:
                for replacement in (None, True, False, 1.0, "1", [], {}, 0, -1, 1 << 64):
                    value = deepcopy(EXPECTED)
                    value[key][slot] = replacement
                    self.refused(frame(value))
        for device in (None, True, 28, "0:028", "00:28", "1:28", "0:-1", "0:4294967296", "0:0", "0:29", "0:28/", CANARY):
            value = deepcopy(EXPECTED)
            value["mount"][2] = device
            self.refused(frame(value))
        for slot in (3, 4):
            for path in (None, True, [], CANARY, "/sys/fs/cgroup/child", "/sys/fs/cgroup/", "\\057"):
                value = deepcopy(EXPECTED)
                value["mount"][slot] = path
                self.refused(frame(value))
        for slot, replacement in ((2, 511), (2, 513), (3, 4294967295), (3, 4294967297), (0, 29)):
            value = deepcopy(EXPECTED)
            value["controller"][slot] = replacement
            self.refused(frame(value))
        # Independent Linux dev_t mapping for minor=300, not an equal decimal.
        value = deepcopy(EXPECTED)
        value["mount"][2], value["controller"][0] = "0:300", 1048620
        self.assertEqual(parse_bootstrap_log(frame(value), NONCE)["controller"][0], 1048620)

    def test_static_single_printf_matches_independent_literal_frame(self):
        match = re.search(r"    printf '([^']+)' (.+) \|\| fail", BOOTSTRAP)
        self.assertIsNotNone(match)
        self.assertEqual(match[2], '"$nonce" "$start" "$uid" "$pidns" "$mountns" "$cgroupns" "$mount_id" "$parent_id" "$mount_device" "$initial_device" "$initial_inode"')
        self.assertTrue(match[1].endswith("\\n"))
        rendered = match[1][:-2] % (NONCE, 123456, 0, 4026533001, 4026533002, 4026533003, 101, 99, "0:28", 28, 2)
        self.assertEqual(rendered.encode("ascii"), b"DOCKERLENS_OUTER_BOOTSTRAP_V1 " + PAYLOAD)

    def test_every_shell_assignment_is_scoped_and_fake_exported_values_restore(self):
        declarations = re.findall(r"^    local ([^\n]+) \|\| fail$", BOOTSTRAP, re.MULTILINE)
        self.assertTrue(declarations)
        self.assertEqual(len(declarations), BOOTSTRAP.count("    local "))
        locals_ = set(" ".join(declarations).split())
        written = set(re.findall(r"(?:^|[;\s])([a-zA-Z_][a-zA-Z_0-9]*)=", BOOTSTRAP, re.MULTILINE))
        for targets in re.findall(r"read -r ([a-zA-Z_][a-zA-Z_0-9]*(?: [a-zA-Z_][a-zA-Z_0-9]*)*)", BOOTSTRAP):
            written.update(targets.split())
        self.assertEqual(written - locals_, set())
        self.assertIn("IFS", locals_)
        # Exercise only an authored local-scope function, NOT BOOTSTRAP. The
        # environment is fabricated; no host environment or procfs is observed.
        names = sorted(locals_ - {"IFS"})
        environment = {name: "CANARY_" + name for name in names}
        environment["PATH"] = "/usr/bin:/bin"
        probe = 'before_ifs=$IFS\nscope_probe() {\n'
        probe += "\n".join("local " + declaration for declaration in declarations) + "\n"
        probe += "\n".join(name + "=changed" for name in sorted(locals_)) + "\n}\nscope_probe\n"
        probe += "\n".join('[ "$' + name + '" = "CANARY_' + name + '" ] || exit 1' for name in names)
        probe += '\n[ "$IFS" = "$before_ifs" ] || exit 1\n'
        result = subprocess.run(["/bin/sh", "-c", probe], env=environment, capture_output=True, text=True, check=False)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))

    def test_failed_local_declaration_refuses_before_observation_or_mutation(self):
        # Only the guarded declarations execute, never BOOTSTRAP or /proc.
        declarations = [line for line in BOOTSTRAP.splitlines() if line.startswith("    local ")]
        # Do not redefine the real local builtin: dash rejects that function
        # name. Substitute only the primitive, preserving the actual guards.
        injected = [line.replace("local ", "scope_local_failure ", 1) for line in declarations]
        program = "fail() { exit 73; }\nscope_local_failure() { return 1; }\nscope_probe() {\n"
        program += "\n".join(injected) + "\n    printf UNSAFE\n}\nscope_probe\n"
        result = subprocess.run(["/bin/sh", "-c", program], env={}, capture_output=True, timeout=2, check=False)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (73, b"", b""))

    def test_duplicate_malformed_json_unicode_and_nonfinite_are_closed(self):
        for payload in (PAYLOAD.replace(b'"pid":1', b'"pid":1,"pid":1'),
                        PAYLOAD.replace(b'"uid":0', b'"uid":NaN'),
                        PAYLOAD.replace(b'"uid":0', b'"uid":Infinity'),
                        PAYLOAD.replace(b'"uid":0', b'"uid":-Infinity'),
                        PAYLOAD + b" trailing " + CANARY.encode(), PAYLOAD[:-1],
                        PAYLOAD.replace(b"0::/", b"\xff"), b"[" * 2000 + b"]" * 2000):
            self.refused(STAMP + b" stdout F DOCKERLENS_OUTER_BOOTSTRAP_V1 " + payload + b"\n")

    def test_first_stdout_nonce_duplicate_marker_fragments_and_log_custody(self):
        for raw in (b"", FRAME[:-1], FRAME + b"unfinished", FRAME + b"\n", FRAME + FRAME,
                    STAMP + b" stdout F preceding\n" + FRAME,
                    FRAME.replace(b" stdout F ", b" stdout P ", 1),
                    STAMP + b" stderr P fragment\n" + FRAME,
                    FRAME + STAMP + b" stderr P fragment\n",
                    FRAME.replace(b" stdout F ", b" unknown F ", 1),
                    FRAME.replace(b" stdout F ", b" stdout X ", 1),
                    FRAME.replace(b"DOCKERLENS_OUTER_BOOTSTRAP_V1 ", b"", 1),
                    FRAME.replace(NONCE.encode(), b"a" * 64),
                    STAMP + b" stderr F DOCKERLENS_OUTER_BOOTSTRAP_V1 " + PAYLOAD + b"\n" + FRAME,
                    FRAME + STAMP + b" stderr F text DOCKERLENS_OUTER_BOOTSTRAP_V1 text\n",
                    FRAME[:-1] + b" " * 1024 + b"\n",
                    FRAME + STAMP + b" stdout F " + b"x" * 16384 + b"\n"):
            self.refused(raw)
        for raw in (None, bytearray(FRAME), FRAME.decode()):
            self.refused(raw)
        padding = b"x" * (16384 - len(FRAME) - len(STAMP) - len(b" stdout F \n"))
        self.assertEqual(parse_bootstrap_log(FRAME + STAMP + b" stdout F " + padding + b"\n", NONCE), EXPECTED)

    def test_calendar_rfc3339nano_offset_and_timestamp_bounds(self):
        for stamp in (b"2024-02-29T23:59:59Z", b"2026-10-19T12:34:56.1+01:30", b"2026-10-19T12:34:56.123456789-23:59"):
            self.assertEqual(parse_bootstrap_log(FRAME.replace(STAMP, stamp), NONCE), EXPECTED)
        for stamp in (b"2026-02-29T12:34:56Z", b"0000-01-01T00:00:00Z", b"2026-13-01T00:00:00Z",
                      b"2026-10-19T24:00:00Z", b"2026-10-19T00:60:00Z", b"2026-10-19T00:00:60Z",
                      b"2026-10-19T12:34:56.Z", b"2026-10-19T12:34:56.1234567890Z",
                      b"2026-10-19 12:34:56Z", b"2026-10-19T12:34:56+24:00", b"2026-10-19T12:34:56+00:60",
                      b"2026-10-19T12:34:56", b"2026-10-19T12:34:56ZZ", CANARY.encode()):
            self.refused(FRAME.replace(STAMP, stamp))

    def test_static_source_original_pid_root_object_rechecks_and_exact_handoff(self):
        self.assertIn('[ "$$" = 1 ] || fail', BOOTSTRAP)
        self.assertIn("done < /proc/self/status", BOOTSTRAP)
        self.assertIn("done < /proc/1/status", BOOTSTRAP)
        self.assertIn("exec 3< /proc/1/stat || fail", BOOTSTRAP)
        self.assertIn('IFS= read -r line <&3 || fail\n    if IFS= read -r extra <&3; then fail; fi\n    [ -z "$extra" ] || fail', BOOTSTRAP)
        self.assertIn('[ "$first" = 1 ] && [ -z "$extra" ]', BOOTSTRAP)
        self.assertIn('[ "$uid" = "$effective" ] && [ "$uid" = "$saved" ] && [ "$uid" = "$filesystem" ]', BOOTSTRAP)
        for path in ("/proc/1/ns/pid", "/proc/1/ns/mnt", "/proc/1/ns/cgroup"):
            self.assertIn(path, BOOTSTRAP)
        self.assertIn('[ "$rows" = 1 ] && [ "$line" = \'0::/\' ]', BOOTSTRAP)
        self.assertIn('[ "$matches" = 1 ] && [ "$major" = 0 ] && [ "$root" = / ] && [ "$point" = /sys/fs/cgroup ]', BOOTSTRAP)
        self.assertEqual(BOOTSTRAP.count("    observe_identity\n"), 2)
        self.assertEqual(BOOTSTRAP.count("    observe_membership\n"), 2)
        self.assertEqual(BOOTSTRAP.count("    observe_mount\n"), 2)
        self.assertEqual(BOOTSTRAP.count("    root_stat /proc/1/fd/9\n"), 2)
        self.assertEqual(BOOTSTRAP.count("    root_stat /sys/fs/cgroup\n"), 2)
        self.assertIn("exec 9< /sys/fs/cgroup || fail", BOOTSTRAP)
        self.assertIn('[ -d /sys/fs/cgroup ] && [ ! -L /sys/fs/cgroup ] || fail\n    exec 9<', BOOTSTRAP)
        self.assertIn('[ -d "$1" ] || fail', BOOTSTRAP)
        self.assertIn('case "$1" in /sys/fs/cgroup) [ ! -L "$1" ] || fail;', BOOTSTRAP)
        self.assertIn("command stat -L -c '%d %i'", BOOTSTRAP)
        self.assertIn("controller_value pids.max 512", BOOTSTRAP)
        self.assertIn("controller_value memory.max 4294967296", BOOTSTRAP)
        self.assertIn('IFS= read -r scalar <&3 || fail\n    [ "$scalar" = "$2" ] || fail', BOOTSTRAP)
        self.assertIn('if IFS= read -r extra <&3; then fail; fi\n    [ -z "$extra" ] || fail', BOOTSTRAP)
        self.assertEqual(BOOTSTRAP.count("printf "), 1)
        self.assertTrue(BOOTSTRAP.endswith('bootstrap "$1" 2>/dev/null\nshift\nexec "$@"\n'))
        self.assertLess(BOOTSTRAP.index("exec 9<&-"), BOOTSTRAP.rindex('exec "$@"'))
        for forbidden in ("export ", "LC_ALL=", "umask", "chmod", "mkdir", "touch ", "mount ", "sudo ",
                          "podman ", "docker ", "nsenter", "apt ", "apk ", "cd ", "exec 2>", "set -e", "$(cat", "$(observe_identity"):
            self.assertNotIn(forbidden, BOOTSTRAP)
        # Syntax parsing only. No shell statement or procfs access is executed.
        result = subprocess.run(["/bin/sh", "-n"], input=BOOTSTRAP, text=True, capture_output=True, check=False)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))
        source = (Path(__file__).resolve().parents[1] / "scripts/native_outer_bootstrap.py").read_text()
        self.assertNotIn("subprocess", source)
        self.assertNotIn("if __name__", source)


    def test_isolated_mount_target_policy_rejects_overmounted_controller_files(self):
        # Only this pure location predicate runs, never BOOTSTRAP or /proc.
        predicate = BOOTSTRAP.split("mount_target() {\n", 1)[1].split("\n}\n", 1)[0]
        program = "fail() { exit 73; }\nmount_target() {\n" + predicate + '\n}\nmount_target "$1" "$2"\n'
        self.assertIn('mount_target "$kind" "$point"\n        case "$kind" in', BOOTSTRAP)
        for kind, point, status in (
                ("tmpfs", "/sys/fs/cgroup/pids.max", 73),
                ("ext4", "/sys/fs/cgroup/memory.max", 73),
                ("tmpfs", "/sys/fs/cgroup", 73),
                ("cgroup2", "/sys/fs/cgroup/child", 73),
                ("cgroup2", "/sys/fs/cgroup/child/pids.max", 73),
                ("sysfs", "/sys", 0),
                ("cgroup2", "/sys/fs/cgroup", 0),
                ("tmpfs", "/sys/fs/cgroup-other", 0)):
            with self.subTest(kind=kind, point=point):
                result = subprocess.run(
                    ["/bin/sh", "-c", program, "dl-mount-target-test", kind, point],
                    env={}, capture_output=True, timeout=2, check=False)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (status, b"", b""))


if __name__ == "__main__":
    unittest.main()
