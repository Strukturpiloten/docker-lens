"""Closed first-refusal projection; isolated fake cargo, no runtime or build."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/native_network_tests.rs").read_text()
PREFIX = "DOCKERLENS_NATIVE_INNER_TOPOLOGY: reason="
STAGE = "DOCKERLENS_NATIVE_CHECK: network_internal_topology"
CLEANUP = "DOCKERLENS_NATIVE_CLEANUP: internal_proof=pass"
FAILED = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;"
PASSED = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;"
CANARY = "private-canary /private/socket 192.0.2.7 token=secret"
# Independently enumerate the public diagnostic vocabulary, not source-derived.
REASONS = (
    "snapshot_array", "snapshot_bounds", "network_count", "held_count", "outer_pools",
    "held_roles", "held_ids", "native_id", "native_name", "duplicate_id", "duplicate_name",
    "scope", "ipam_driver", "builtin_pools", "bridge_membership", "bridge_driver",
    "held_binding", "bridge_ipam", "ipv4_overlap", "retained_set",
)


def function(name):
    start = SOURCE.index("\nfn " + name + "(") + 1
    return SOURCE[start:SOURCE.index("\n}\n", start) + 2]


def tokens(text):
    return " ".join(re.findall(r'"(?:\\.|[^"\\])*"|[A-Za-z_]\w*|[^\s]', text))


class InnerTopologyDiagnosticTests(unittest.TestCase):
    def run_wrapper(self, lines, *, status=101, summary=FAILED, target="native_network",
                    test="live_internal_network_blocks_external_egress"):
        with tempfile.TemporaryDirectory(prefix="dockerlens-inner-topology-control-") as directory:
            tools = Path(directory)
            for name in ("timeout", "grep", "sed", "tail", "date"):
                (tools / name).symlink_to("/usr/bin/" + name)
            cargo = tools / "cargo"
            cargo.write_text(
                f"#!{sys.executable}\nimport sys\n"
                f"if '--list' in sys.argv: print({target + '_tests::' + test + ': test'!r})\n"
                f"else:\n print({chr(10).join([*lines, summary])!r})\n raise SystemExit({status})\n"
            )
            cargo.chmod(0o700)
            return subprocess.run(
                ["/bin/bash", str(ROOT / "scripts/run-exact-native-test.sh"), target, test],
                env={"PATH": str(tools)}, capture_output=True, text=True, timeout=4,
            )

    def test_every_closed_reason_retains_original_failure_stage_status_and_cleanup(self):
        for reason in REASONS:
            with self.subTest(reason=reason):
                line = PREFIX + reason
                result = self.run_wrapper([STAGE, line, CANARY, CLEANUP])
                self.assertEqual((result.returncode, result.stdout), (1, ""))
                self.assertIn("failed (exit 101)", result.stderr)
                for expected in (STAGE, CLEANUP, FAILED, line):
                    self.assertIn(expected + "\n", result.stderr)
                self.assertEqual(result.stderr.count(PREFIX), 1)
                self.assertNotIn(CANARY, result.stderr)

    def test_malformed_near_matches_and_native_canaries_never_cross_whitelist(self):
        valid = PREFIX + "bridge_ipam"
        for line in (
            CANARY, PREFIX + CANARY, PREFIX + "unknown", PREFIX + "BridgeIpam",
            PREFIX + "bridge-ipam", PREFIX + "bridge_ipam_extra", PREFIX + "",
            " " + valid, valid + " ", valid + "\r", valid + "\x1b[0m", "prefix=" + valid,
            valid + " " + CANARY, valid + " reason=ipv4_overlap",
            valid.replace("reason=", "reason ="), valid.replace("TOPOLOGY:", "TOPOLOGY :"),
        ):
            with self.subTest(line=line):
                result = self.run_wrapper([STAGE, line, CLEANUP])
                self.assertEqual(result.returncode, 1)
                self.assertIn("failed (exit 101)", result.stderr)
                self.assertIn(CLEANUP, result.stderr)
                self.assertNotIn(PREFIX, result.stderr)
                self.assertNotIn(CANARY, result.stdout + result.stderr)

    def test_conflicting_or_duplicate_diagnostics_are_unavailable(self):
        for reasons in (("bridge_ipam", "bridge_ipam"), ("bridge_ipam", "ipv4_overlap")):
            result = self.run_wrapper([STAGE, *(PREFIX + reason for reason in reasons), CLEANUP])
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(PREFIX, result.stderr)
            self.assertIn(CLEANUP, result.stderr)

    def test_projection_is_failure_only_at_exact_test_and_original_stage(self):
        line = PREFIX + "ipv4_overlap"
        for stage, target, test in (
            ("DOCKERLENS_NATIVE_CHECK: network_internal_cli_control", "native_network",
             "live_internal_network_blocks_external_egress"),
            (STAGE, "native_network", "live_network_render_matches_engine"),
            (STAGE, "native_target", "live_target_render_matches_engine"),
        ):
            with self.subTest(stage=stage, target=target, test=test):
                result = self.run_wrapper([stage, line, CLEANUP], target=target, test=test)
                self.assertEqual(result.returncode, 1)
                self.assertNotIn(PREFIX, result.stderr)
        passed = self.run_wrapper([STAGE, line, CLEANUP], status=0, summary=PASSED)
        self.assertEqual(passed.returncode, 0)
        self.assertNotIn(PREFIX, passed.stdout + passed.stderr)
        # A diagnostic/cleanup line cannot turn a failing invocation into success.
        failed = self.run_wrapper([STAGE, line, CLEANUP], status=101, summary=PASSED)
        self.assertEqual(failed.returncode, 1)
        self.assertIn("failed (exit 101)", failed.stderr)
        unselected = self.run_wrapper(
            [STAGE, line, CLEANUP], status=0,
            summary="test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;",
        )
        self.assertEqual(unselected.returncode, 1)
        self.assertIn("did not execute exactly once (exit 0)", unselected.stderr)
        self.assertNotIn(PREFIX, unselected.stderr)

    def test_original_predicates_and_short_circuit_order_are_retained(self):
        # Original e40245d predicate order, with one reviewed schema correction:
        # exact builtins accept a present null or empty Config, never absence.
        original = (
            'networks.as_array()', 'retained_topology_names(run)',
            '!bounded_topology_json(&Value::Array(networks.clone()))',
            'networks.len() != expected.len() + 2', 'held_ids.len() != 5', 'outer.is_empty()',
            'held_names.len() != 5 || !held_names.contains(format!("dl-{run}-net").as_str()) || '
            '["proof-internal", "proof-control", "proof-cli-internal", "proof-cli-control",]'
            '.iter().any(|suffix| !held_names.contains(format!("dl-network-{run}-{suffix}").as_str()))',
            'held_values.len() != 5 || held_values.iter()'
            '.any(|id| canonical_inspected_container_id(&json!({"Id": id})).is_none())',
            'canonical_inspected_container_id(network)', 'network.get("Name").and_then(Value::as_str)',
            '!ids.insert(id)', '!names.insert(name)', 'network["Scope"] != "local"',
            'network["IPAM"]["Driver"] != "default"',
            '(name, network["Driver"].as_str()), ("host", Some("host")) | ("none", Some("null"))',
            '!network["IPAM"].get("Config").is_some_and(|config| {'
            'config.is_null() || config.as_array().is_some_and(Vec::is_empty)})',
            '!expected.iter().any(|expected| expected == name)', 'network["Driver"] != "bridge"',
            'held_ids.iter().any(|(held_name, held_id)| held_name == name && held_id != id)',
            'topology_ipam(&network["IPAM"]["Config"])',
            'pools.iter().filter(|pool| pool.address.is_ipv4())'
            '.any(|pool| outer.iter().any(|other| pool.overlaps(*other)))',
            'expected.iter().all(|name| names.contains(name.as_str())) && names.contains("host") '
            '&& names.contains("none") && held_ids.iter().all(|(name, _)| expected.contains(name))',
        )
        assessment = tokens(function("assess_inner_topology"))
        cursor = 0
        for predicate in original:
            needle = tokens(predicate)
            with self.subTest(predicate=predicate):
                cursor = assessment.index(needle, cursor) + len(needle)
        self.assertIn('assess_inner_topology(networks, run, held_ids, outer).is_ok()',
                      function("inner_topology_disjoint"))
        self.assertEqual(assessment.count(tokens('pool.overlaps(*other)')), 1)

    def test_nullable_config_exception_is_only_inside_exact_builtin_branch(self):
        assessment = function("assess_inner_topology")
        builtin = assessment.split('if builtin {', 1)[1].split('continue;', 1)[0]
        self.assertIn(tokens('!network["IPAM"].get("Config").is_some_and(|config| {'
                             'config.is_null() || config.as_array().is_some_and(Vec::is_empty)})'),
                      tokens(builtin))
        self.assertIn('return Err(InnerTopologyRefusal::BuiltinPools);', builtin)
        self.assertNotIn('network["IPAM"]["Config"]', builtin)
        self.assertEqual(assessment.count('config.is_null()'), 1)
        before, after = assessment.split('if builtin {', 1)
        self.assertIn(tokens('matches!((name, network["Driver"].as_str()),'
                             '("host", Some("host")) | ("none", Some("null")))'), tokens(before))
        bridge = after.split('continue;', 1)[1]
        self.assertIn('let Some(pools) = topology_ipam(&network["IPAM"]["Config"])', bridge)
        self.assertNotIn('is_null()', bridge)

    def test_one_evaluation_best_effort_static_bytes_and_unchanged_owners(self):
        live = function("live_internal_network_blocks_external_egress")
        start = live.index('let networks = read_inner_topology(')
        end = live.index('eprintln!("DOCKERLENS_NATIVE_CHECK: network_internal_sidecar");', start)
        boundary = live[start:end]
        self.assertEqual(boundary.count('assess_inner_topology('), 1)
        self.assertEqual(boundary.count('emit_inner_topology_refusal('), 1)
        self.assertIn('if let Err(reason) = result', boundary)
        self.assertIn('result.is_ok()', boundary)
        self.assertIn('"all retained inner bridge pools are disjoint from actual outer pools"', boundary)
        emitter = function("emit_inner_topology_refusal")
        self.assertIn('let _ = output.write_all(reason.diagnostic());', emitter)
        for forbidden in ('unwrap(', 'expect(', 'eprintln!', 'format!', 'panic!', 'Command::'):
            self.assertNotIn(forbidden, emitter)
        diagnostic = SOURCE.split('impl InnerTopologyRefusal {', 1)[1].split('\n}\n', 1)[0]
        categories = re.findall(r'b"DOCKERLENS_NATIVE_INNER_TOPOLOGY: reason=(\w+)\\n"', diagnostic)
        self.assertEqual(categories, list(REASONS))
        coordinator = (ROOT / "scripts/native-conformance.sh").read_text()
        invocations = re.findall(r'^\s*"\$\(dirname "\$0"\)/run-exact-native-test.sh" ',
                                 coordinator, re.MULTILINE)
        self.assertEqual(len(invocations), 23)
        self.assertIn('resources.require_budget(8);', live)
        self.assertIn('NATIVE_NETWORK_TEST_DEADLINE_EPOCH', SOURCE)


if __name__ == "__main__":
    unittest.main()
