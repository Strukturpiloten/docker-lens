"""Source/syntax guards and synthetic format sizing; never execute any worker or observer."""

import json
from copy import deepcopy
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
                                       "PIDS_CONTROL", "PIDS_PREFLIGHT", "PIDS_COORDINATE_PREFIX"})
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

    def test_actual_closed_stages_precede_each_named_operation(self):
        source = SOURCE.read_text()
        body = re.sub(r"\s+", " ", source.split("fn live_pids_limit_effects_match_engine()", 1)[1].split("\n#[test]", 1)[0])
        context = {
            "Context": "let daemon_uid = run.context();",
            "Image": "let image = image_snapshot(&run);",
            "OuterObserver": "let context = pids_lines(",
            "DaemonIdentity": 'let daemon: Vec<_> = pids_field(&context, "D")',
            "OuterPidsResolve": 'let outer_pids = pids_resolve(',
            "OuterMemoryResolve": 'let outer_memory = pids_resolve(',
            "Acquisition": "let acquisition = pids_acquisition(&run);",
            "FinalSnapshots": "assert!( !run.image_attempted",
            "Proof": "private.require_active(true); target.publish(&proof); private.require_active(true);",
        }
        cases = {
            "Preflight": "let preflight_lines = pids_lines(",
            "Create": "pids_create(&mut run, index);",
            "Start": "start(&run, index);",
            "Inspect": "let inspected = pids_configured(&run, index, &image);",
            "PrivateIdentity": "let private = docker(",
            "BaselineScan": "let baseline_lines = pids_scan(",
            "LeafPidsResolve": "let mut pids = pids_resolve(",
            "LeafMemoryResolve": "let mut memory = pids_resolve(",
            "BaselineController": "let (baseline, event_source) =",
            "WorkStart": 'pids_control(&run, outer_init, namespace, init_start, uid, "START");',
            "HeldScan": "let held_lines =",
            "HeldController": "let (held, held_source) =",
            "Release": 'pids_control(&run, outer_init, namespace, init_start, uid, "RELEASE");',
            "RestoredScan": "let restored_lines = pids_scan(",
            "RestoredController": "let (restored, restored_source) =",
            "FinalInspect": "assert!( pids_configured(&run, index, &image)",
        }
        for index, operations in (("None", context), ("Some(index)", cases)):
            for operation, following in operations.items():
                with self.subTest(operation=operation):
                    self.assertIn(f"pids_stage({index}, PidsOperation::{operation}); {following}", body)
        calls = re.findall(r"pids_stage\((None|Some\(index\)), PidsOperation::(\w+)\);", body)
        self.assertEqual(set(calls), {("None", item) for item in context} | {("Some(index)", item) for item in cases})
        self.assertEqual(len(calls), 25)
        self.assertEqual(body.count("target.publish(&proof);"), 1)
        labels = dict(re.findall(r'Self::(\w+) => "([a-z_]+)"', source.split("impl PidsOperation", 1)[1].split("fn pids_stage", 1)[0]))
        self.assertEqual(set(labels), set(context) | set(cases))
        self.assertEqual(set(labels.values()), {
            "context", "image", "outer_observer", "daemon_identity", "outer_pids_resolve", "outer_memory_resolve",
            "preflight", "create", "start", "inspect", "private_identity", "baseline_scan", "leaf_pids_resolve",
            "leaf_memory_resolve", "baseline_controller", "work_start", "held_scan", "held_controller", "release",
            "restored_scan", "restored_controller", "final_inspect", "acquisition", "final_snapshots", "proof",
        })
        self.assertEqual(source.count("eprintln!("), 3)

    def test_resolution_diagnostics_do_not_change_mapping_or_assertion(self):
        source = SOURCE.read_text()
        resolver = source.split("fn pids_resolve(", 1)[1].split("fn pids_cleanup_with", 1)[0]
        self.assertIn('pids_safe_path(fields[3])', resolver)
        self.assertIn('pids_safe_path(fields[4])', resolver)
        self.assertIn('selected_path.strip_prefix(&root)', resolver)
        self.assertIn('owner_path.strip_prefix(&root)', resolver)
        self.assertIn('(!descendant || path != outer_path) && path.starts_with(&outer_path)', resolver)
        self.assertIn('equal_owner |= descendant && path == outer_path;', resolver)
        self.assertIn('outside_owner |= !path.starts_with(&outer_path);', resolver)
        self.assertIn('pids_owned_relation(equal_owner, outside_owner)', resolver)
        self.assertLess(resolver.index("continue;"), resolver.index("eligible_mount = true;"))
        self.assertLess(resolver.index("owner_path.strip_prefix(&root)"), resolver.index("rooted_mount = true;"))
        self.assertLess(resolver.index("rooted_mount = true;"), resolver.index("path.starts_with(&outer_path)"))
        self.assertIn("pids_resolution_failure(eligible_mount, rooted_mount, candidates.len())", resolver)
        self.assertRegex(resolver, r'assert!\(\s*candidates.len\(\) == 1,\s*"unique controller mount-root resolution"')
        for name in ("pids_resolution_handles_v1_comount_and_v2_nonroot_mount_roots",
                     "pids_resolution_keeps_untranslated_sibling_duplicate_and_strict_descendant_refusals",
                     "pids_resolution_diagnostic_classification_uses_only_existing_predicate_observations",
                     "pids_resolution_ownership_diagnostics_distinguish_equal_and_outside_boundaries"):
            self.assertIn("fn " + name + "()", source)

    def test_controller_diagnostics_preserve_original_short_circuit_and_never_query(self):
        source = SOURCE.read_text()
        controller = source.split("fn pids_controller(", 1)[1].split("fn pids_control(", 1)[0]
        original = ('assert!( members == expected && pids_u64(pids_field(&lines, "CURRENT")) '
                    '== rows.len() as u64, "exclusive single-threaded leaf membership" );')
        self.assertIn(original, re.sub(r"\s+", " ", controller))
        diagnostic = "pids_controller_failure(members == expected, &lines, rows.len())"
        self.assertLess(controller.index(diagnostic), controller.index('"exclusive single-threaded'))
        helper = source.split("fn pids_controller_failure(", 1)[1].split("// Authored", 1)[0]
        for required in ('line.strip_prefix("CURRENT ")', 'currents.next()?', 'currents.next().is_some()',
                         'current.is_empty()', 'byte.is_ascii_digit()', "current.starts_with('0')",
                         'current.parse::<u64>().ok()?', '(true, true) => None'):
            self.assertIn(required, helper)
        for forbidden in ("pids_field(", "pids_u64(", "assert!", "unwrap", "panic!", "run.",
                          "pids_shell(", "docker(", "eprintln!"):
            self.assertNotIn(forbidden, helper)
        labels = re.findall(r'Some\("([a-z_]+)"\)', helper)
        self.assertEqual(set(labels), {"member_ids_mismatch", "current_count_mismatch",
                                       "members_and_current_mismatch"})
        self.assertEqual(controller.count("pids_shell("), 1)
        self.assertIn('fn pids_controller_diagnostics_use_only_canonical_existing_current_observations()', source)


    def test_raw_frame_regressions_share_live_controller_parser_before_packing(self):
        source = SOURCE.read_text()
        live = source.split("fn pids_controller(", 1)[1].split("fn pids_controller_frame(", 1)[0]
        pure = source.split("fn pids_controller_frame(", 1)[1].split("fn pids_control(", 1)[0]
        self.assertEqual(live.count("pids_shell("), 1)
        delegation = "pids_controller_frame(bytes, rows, phase, pids, memory, coordinates)"
        self.assertEqual(live.count(delegation), 1)
        self.assertLess(live.index('pids["kind"] == memory["kind"]'), live.index("pids_shell("))
        self.assertLess(live.index("pids_shell("), live.index(delegation))
        for forbidden in ("pids_shell(", "run.", "docker("):
            self.assertNotIn(forbidden, pure)
        self.assertIn("let lines = pids_lines(", pure)
        self.assertIn('rows.iter().map(|row| row[0].as_u64().unwrap())', pure)
        self.assertLess(pure.index('"exclusive single-threaded leaf membership"'), pure.index("let packed:"))
        for regression in (
            "pids_raw_frames_compare_outer_members_before_delta_encoding",
            "pids_raw_controller_frames_keep_membership_and_parser_refusals",
            "pids_raw_scan_frames_keep_namespace_binding_and_duplicate_refusals",
        ):
            self.assertIn(f"fn {regression}()", source)
        fixture = source.split("fn pids_raw_frame_fixture()", 1)[1].split("fn pids_raw_scan_rows(", 1)[0]
        self.assertIn('R 903 9 2579 50008 1000 903 79 9', fixture)
        self.assertIn('MEMBER 2579\\nMEMBER 4317\\nMEMBER 903', fixture)

    def test_coordinate_prefix_is_inline_builtin_shared_and_pid_anchored(self):
        source = SOURCE.read_text()
        scripts = shell_constants()
        prefix = scripts["PIDS_COORDINATE_PREFIX"]
        shell = source.split("fn pids_shell(", 1)[1].split("struct PidsCoordinates", 1)[0]
        self.assertIn("[PIDS_OUTER_CONTEXT, PIDS_SCAN, PIDS_CONTROLLER_READ].contains(&script)", shell)
        self.assertEqual(shell.count("PIDS_COORDINATE_PREFIX"), 1)
        self.assertIn('format!("{PIDS_COORDINATE_PREFIX}\\n{script}")', shell)
        for fragment in ('done </proc/self/status', '[ "$coords_lines" -le 128 ]',
                         '[ "$coords_pid_seen" -eq 0 ]', '[ "$coords_chain_seen" -eq 0 ]',
                         '[ -z "$coords_extra" ]', '[ "$coords_count" -le 8 ]',
                         '[ "$coords_count" -eq 1 ]', '[ "$coords_pid" = "$$" ]',
                         '[ "$coords_first" = "$$" ]', '[ "$$" -le 4194304 ]',
                         "printf 'SELF %s %s %s\\n'", "''|0|0[0-9]*|*[!0-9]*) exit 79"):
            self.assertIn(fragment, prefix)
        for namespace in ("pid", "mnt", "cgroup"):
            self.assertIn(f'readlink "/proc/$coords_pid/ns/{namespace}"', prefix)
        for forbidden in ("$(", "set --", "cat ", "/proc/self/ns/", "nsenter", "/host/proc"):
            self.assertNotIn(forbidden, prefix.replace("$((", ""))
        for name in ("PIDS_OUTER_CONTEXT", "PIDS_SCAN", "PIDS_CONTROLLER_READ"):
            self.assertNotIn("/proc/self/ns/", scripts[name])
            result = subprocess.run(["sh", "-n"], input=prefix + "\n" + scripts[name],
                                    text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_coordinate_accumulation_precedes_comparison_and_private_tuple_compaction(self):
        source = SOURCE.read_text()
        controller = source.split("fn pids_controller_frame(", 1)[1].split("fn pids_control(", 1)[0]
        self.assertLess(controller.index("coordinates.observe(&lines)"), controller.index("for mapping in"))
        self.assertLess(controller.index("coordinates.observe(&lines)"), controller.index("members == expected"))
        live = re.sub(r"\s+", " ", source.split("fn live_pids_limit_effects_match_engine()", 1)[1].split("\n#[test]", 1)[0])
        authenticated = 'PidsCoordinates::authenticated(&context, &private.value["boundary"])'
        self.assertEqual(live.count(authenticated), 1)
        self.assertNotIn("PidsCoordinates::new(", live)
        self.assertEqual(live.count("for index in 0..6 {"), 1)
        self.assertEqual(live.count("pids_scan("), 3)
        self.assertEqual(live.count("pids_controller("), 3)
        self.assertEqual(controller.count("coordinates.observe(&lines)"), 1)
        scan_body = source.split("fn pids_scan(", 1)[1].split("fn pids_nproc(", 1)[0]
        self.assertEqual(scan_body.count("coordinates.observe(&lines)"), 1)
        positions = [live.index(authenticated)]
        for rows, phase in (("baseline", "ready"), ("held", "exit_barrier"), ("restored", "idle")):
            scan = f'pids_scan(&run, &context, namespace, depth, init_start, "{phase}", &mut coordinates)'
            controller_call = f'pids_controller(&run, &{rows}_rows, "{phase}", &mut pids, &mut memory, &mut coordinates)'
            # Rustfmt may wrap argument lists with a trailing comma.
            normalized = re.sub(r"\(\s+", "(", re.sub(r",\s*\)", ")", live))
            positions.extend((normalized.index(scan), normalized.index(controller_call)))
        self.assertEqual(positions, sorted(positions))
        self.assertLess(live.index("coordinates.finish()"), live.index("pids_private_v2(&mut proof, coordinates)"))
        # The authenticated constructor still contributes the first witness;
        # every subsequent observer authenticates before retaining its tuple.
        constructor = source.split("fn authenticated(", 1)[1].split("fn authenticate(", 1)[0]
        self.assertIn("boundary: Some(boundary.clone())", constructor)
        self.assertIn("coordinates.observe(context);", constructor)
        observer = source.split("fn observe(", 1)[1].split("fn finish(", 1)[0]
        self.assertLess(observer.index("self.authenticate(lines);"), observer.index('pids_field(lines, "SELF")'))
        self.assertLess(observer.index("self.witnesses.len() < 37"), observer.index("self.witnesses.push("))
        finish = source.split("fn finish(", 1)[1].split("const PIDS_PHASE_FIELDS:", 1)[0]
        self.assertIn("self.witnesses.len() == 37", finish)
        packing = source.split("fn pids_private_v2(", 1)[1].split("fn pids_proof_budget(", 1)[0]
        self.assertLess(packing.index("coordinates.len() == 37"), packing.index('proof["coordinates"]'))
        self.assertIn('const PIDS_CONTRACT: &str = "pids-limit-v2";', source)
        self.assertIn('const PIDS_FILENAME: &str = "pids-limit-v2.json";', source)
        self.assertIn('"schema_version":2', source)
        self.assertIn("PIDS_PROOF_BYTES - PIDS_OUTER_BINDING_RESERVE", source)
        self.assertIn("const PIDS_OUTER_BINDING_RESERVE: usize = 1024;", source)

    def test_compact_layout_losslessly_fits_historical_fixtures_with_future_reserve(self):
        from test_native_pids_limit_proof import fixture

        fields = ("rows", "members", "pids_current", "pids_max", "denials", "oom_kills",
                  "outer_pids", "outer_memory", "ancestor_headroom", "phase")
        source = SOURCE.read_text()
        table = source.split("const PIDS_PHASE_FIELDS:", 1)[1].split("];", 1)[0]
        self.assertEqual(tuple(re.findall(r'"([a-z_]+)"', table)), fields)
        size = lambda value: len(json.dumps(value, separators=(",", ":")).encode())
        for lane in ("debian11-rootful", "debian11-rootless", "upstream-rootful", "upstream-rootless"):
            for kind in ("v1", "v2"):
                for nested in (False, True):
                    with self.subTest(lane=lane, kind=kind, nested=nested):
                        original = fixture(lane, kind, nested)
                        compact = deepcopy(original)
                        compact.update(schema_version=2, contract="pids-limit-v2")
                        for case in compact["cases"]:
                            for phase in ("baseline", "held", "restored"):
                                self.assertEqual(set(case[phase]), set(fields))
                                case[phase] = [case[phase][key] for key in fields]
                        self.assertEqual(size(original) - size(compact), 2178)
                        compact["coordinates"] = [[4194304, 0, [0], 0, 0, 0] for _ in range(37)]
                        self.assertEqual(size(original) - size(compact), 1348)
                        self.assertLessEqual(size(compact), 15360)
                        expanded = deepcopy(compact)
                        del expanded["coordinates"]
                        expanded.update(schema_version=1, contract="pids-limit-v1")
                        for case in expanded["cases"]:
                            for phase in ("baseline", "held", "restored"):
                                case[phase] = dict(zip(fields, case[phase], strict=True))
                        self.assertEqual(expanded, original)


if __name__ == "__main__":
    unittest.main()
