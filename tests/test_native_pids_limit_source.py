"""Prepared-source guards and sh -n only; never execute any worker or observer."""

import json
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/native_pids_limit_tests.rs"


def shell_constants():
    source = SOURCE.read_text()
    result = dict(re.findall(r'const (PIDS_[A-Z_]+): &str = r#"(.*?)"#;', source, re.S))
    worker = re.search(r'const PIDS_WORKER: &str = ("(?:[^"\\]|\\.)*");', source)
    if worker is None:
        raise ValueError("missing finite worker")
    result["PIDS_WORKER"] = json.loads(worker[1])
    return result


class PidsLimitSourceTests(unittest.TestCase):
    def test_every_prepared_shell_constant_parses_without_running(self):
        scripts = shell_constants()
        self.assertEqual(set(scripts), {"PIDS_PARENT", "PIDS_WORKER", "PIDS_PRIVATE_IDENTITY",
                                       "PIDS_OUTER_CONTEXT", "PIDS_SCAN", "PIDS_CONTROLLER_READ",
                                       "PIDS_CONTROL", "PIDS_PREFLIGHT"})
        for name, script in scripts.items():
            with self.subTest(name=name):
                result = subprocess.run(["sh", "-n"], input=script, text=True, capture_output=True, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_worker_is_bounded_and_original_exit_barrier_does_not_fork(self):
        scripts = shell_constants()
        worker = scripts["PIDS_WORKER"]
        self.assertIn('"$n" -lt 32', worker)
        self.assertLess(worker.index("trap 'code=$?"), worker.index('while [ "$n"'))
        self.assertIn('IFS= read -r release', worker)
        self.assertIn('IFS= read -r held <&5', worker)
        self.assertNotIn("sleep", worker)
        self.assertNotIn("$(", worker.replace("$((", ""))
        self.assertIn('jobs >/dev/null', scripts["PIDS_PARENT"])

    def test_static_request_and_duplicated_inspect_fields_keep_unchanged_envelopes(self):
        scripts = shell_constants()
        argv = ["/bin/busybox", "ash", "-c", scripts["PIDS_PARENT"],
                "dl-pids-parent", scripts["PIDS_WORKER"]]
        body = {"Image": "docker.io/library/busybox:1.37.0@sha256:" + "b" * 64,
                "Cmd": argv, "Labels": {"io.dockerlens.native-run": "abcdefgh"},
                "HostConfig": {"PidsLimit": 16}}
        self.assertLessEqual(len(json.dumps(body, separators=(",", ":")).encode()), 4096)
        # Only these authored fields are predictable offline, not the complete
        # native inspect envelope. Leave >=5KiB for other fields/framing; real
        # cleanup must still pass the unchanged 8192-byte capture bound.
        duplicated = {"Config": {"Cmd": argv, "Entrypoint": None},
                      "Path": argv[0], "Args": argv[1:]}
        self.assertLessEqual(len(json.dumps(duplicated, separators=(",", ":")).encode()), 8192 - 5120)

    def test_mapping_reads_owned_outer_context_and_never_guesses_inspect_pid(self):
        scripts = shell_constants()
        self.assertIn('readlink /proc/1/ns/pid', scripts["PIDS_PRIVATE_IDENTITY"])
        self.assertIn('"$visited" -le 512', scripts["PIDS_SCAN"])
        self.assertIn('"$actual" = "pid:[$namespace]"', scripts["PIDS_SCAN"])
        self.assertIn('"$started" = "$expected_start"', scripts["PIDS_SCAN"])
        self.assertIn('NSpid:', scripts["PIDS_SCAN"])
        source = SOURCE.read_text()
        self.assertRegex(source, r'chain\[\s*depth\s+as\s+usize\s*-\s*1\s*\]')
        self.assertNotIn("nsenter", "\n".join(scripts.values()))
        self.assertNotIn("/host/proc", source)
        self.assertNotIn("/sys/fs/cgroup/docker", source)

    def test_control_rechecks_original_pid1_and_open_fifo_identity_before_writing(self):
        scripts = shell_constants()
        control = scripts["PIDS_CONTROL"]
        for expected in ('"$actual_start" = "$expected_start"',
                         '"$uid" = "$expected_uid"', '"pid:[$namespace]"',
                         'test /proc/self/fd/9 -ef "$root/parent"; check_init'):
            self.assertIn(expected, control)
        self.assertLess(control.rindex("check_init"), control.index("printf '%s\\n'"))
        self.assertEqual(scripts["PIDS_SCAN"].count('test "$directory/exe" -ef'), 2)
        self.assertIn('stable owned observer namespaces at every phase', SOURCE.read_text())

    def test_disappearing_non_pid1_never_reaches_initial_executable_or_stat_probe(self):
        scan = shell_constants()["PIDS_SCAN"]
        initial = scan.split('[ -n "$init" ];', 1)[0].split('for directory in /proc/[0-9]*; do', 1)[1]
        # Model the initial resolver's operation ordering, not a replacement
        # shell/worker. A child whose status was read can disappear after its
        # namespace lookup; its exe/stat probes would then abort under set -e.
        # Derive order from the actual source so moving the private-PID guard
        # back below a probe makes this regression fail without executing it.
        operations = sorted((initial.index(fragment), operation) for fragment, operation in (
            ('[ "$private" = 1 ] || continue', "private_pid_guard"),
            ('actual=$(readlink "$directory/ns/pid")', "namespace"),
            ('test "$directory/exe" -ef', "executable"),
            ('read -r line <"$directory/stat"', "stat")))
        records = [{"outer_pid": 1001, "nspid": [1001, 21, 2], "namespace": 300,
                    "start": 100001, "missing_after_namespace": True},
                   {"outer_pid": 1000, "nspid": [1000, 20, 1], "namespace": 300,
                    "start": 100000, "missing_after_namespace": False}]
        probes, selected = [], []
        for record in records:
            for _, operation in operations:
                if operation == "private_pid_guard":
                    if record["nspid"][-1] != 1:
                        break
                    continue
                probes.append((record["outer_pid"], operation))
                if operation == "namespace":
                    if record["namespace"] != 300:
                        break
                else:
                    self.assertFalse(record["missing_after_namespace"], "expected exiting child must not be probed")
                    if operation == "stat":
                        self.assertEqual(record["start"], 100000)
                        selected.append(record["outer_pid"])
        self.assertEqual(selected, [1000])
        self.assertEqual(probes, [(1000, "namespace"), (1000, "executable"), (1000, "stat")])
        # The post-barrier scan must still validate every actual member. The
        # early PID1-only guard must not leak into held/restored inventory.
        complete = scan.split('[ "$ready" -eq 1 ]', 1)[1]
        self.assertNotIn('[ "$private" = 1 ] || continue', complete)
        self.assertLess(complete.index('test "$directory/exe" -ef'), complete.index("printf 'R "))
        self.assertIn('[ "$private" != 1 ] || {', complete)

    def test_leaf_counters_membership_headroom_and_guard_are_explicit(self):
        source = SOURCE.read_text()
        for expected in ("pids.events.local", "pids.events", "cgroup.procs", "memory.events.local",
                         "memory.oom_control", "headroom >= 128", "outer_pids <= 384",
                         "outer_memory <= 3221225472", "State.Pid bound", "pids_cleanup_with",
                         "OuterTeardownRequired", "run.attempted[index] = true", "16 * 1024"):
            self.assertIn(expected, source)
        self.assertIn("members == expected", source)
        self.assertIn("actual original-worker EXIT barrier status", source)
        self.assertIn("specific C-locale native EAGAIN envelope", source)
        guard = source.split("fn pids_cleanup_with", 1)[1].split("fn pids_create", 1)[0]
        self.assertLess(guard.index("if complete"), guard.index("inner()"))
        self.assertNotIn("inspect(", guard)

    def test_requests_and_capture_are_finite_and_keep_product_grants_absent(self):
        source = SOURCE.read_text()
        self.assertIn('[("finite16", 16), ("finite64", 64), ("unlimited", -1)]', source)
        self.assertIn('request == literal', source)
        self.assertIn('"--pids-limit"', source)
        self.assertIn('PidsLimit::Unlimited', source)
        self.assertIn('Selector::ContainerIds', source)
        self.assertRegex(source, r'\bmax_selected_resources\s*:\s*6\b')
        self.assertIn('"capability_admission":[]', source)
        self.assertIn('"catalogue_admission":false', source)
        self.assertNotIn("ResourceSupportAssessment", source)


if __name__ == "__main__":
    unittest.main()
