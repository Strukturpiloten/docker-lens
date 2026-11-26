"""Strict CLI precontrol wiring and closed-marker tests; no native client runs."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/native_network_tests.rs").read_text()
SELECTED = "native_network_tests::live_internal_network_blocks_external_egress"
CLI_MARKER = "DOCKERLENS_NATIVE_CHECK: network_internal_cli_control"
PEER_MARKER = "DOCKERLENS_NATIVE_CHECK: network_internal_peers"
TARGET_MARKER = "DOCKERLENS_NATIVE_CHECK: network_internal_control"
FAILED = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;"
PASSED = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;"


def function(name):
    match = re.search(r'\nfn ' + re.escape(name) + r'(?:<[^>]*>)?\(', SOURCE)
    if match is None:
        raise AssertionError("missing expected Rust function: " + name)
    start = match.start() + 1
    return SOURCE[start:SOURCE.index("\n}\n", start) + 2]


def tokens(text):
    return re.findall(r'"(?:\\.|[^"\\])*"|[A-Za-z_]\w*|[^\s]', text)


class NativeCliEgressControlTests(unittest.TestCase):
    def test_fixed_client_is_registered_before_create_start_custody_and_strict_positive(self):
        live = function("live_internal_network_blocks_external_egress")
        self.assertIn('let cli_control_client = format!("dl-network-{run_id}-proof-cli-control-client");', live)
        start = live.index('eprintln!("' + CLI_MARKER + '");')
        end = live.index('eprintln!("' + TARGET_MARKER + '");', start)
        precontrol = live[start:end]
        expected_create = '''proof_cli_ok(&resources, &[
            "create", "--name", &cli_control_client, "--label", &owner,
            "--network", &cli_control, &image, "sh", "-c", "sleep 180",
        ],);'''
        expected_wget = '''proof_cli_ok(&resources, &[
            "exec", &cli_control_client, "wget", "-Y", "off", "-T", "2", "-qO-", &external_url,
        ],);'''
        self.assertIn(" ".join(tokens(expected_create)), " ".join(tokens(precontrol)))
        self.assertIn(" ".join(tokens(expected_wget)), " ".join(tokens(precontrol)))
        steps = [
            'resources.containers.push(cli_control_client.clone());',
            '"create"',
            'proof_cli_ok(&resources, &["start", &cli_control_client]);',
            'assert_single_homed_running(&resources, &cli_control_client, &cli_control, &api_version);',
            'let cli_control_response = proof_cli_ok(',
            'cli_control_response, b"proof-egress",',
        ]
        offsets = [precontrol.index(step) for step in steps]
        self.assertEqual(offsets, sorted(offsets))
        self.assertEqual(precontrol.count('resources.containers.push('), 1)
        self.assertEqual(precontrol.count('"create"'), 1)
        self.assertEqual(precontrol.count('"wget"'), 1)
        self.assertNotIn('subnet_diagnostics = Some', precontrol)
        self.assertNotIn('catch_unwind', precontrol)
        self.assertNotIn('if ', precontrol)
        self.assertIn('let external_url = format!("http://{sidecar_ip}:18084/");', live[:start])
        self.assertIn('let owner = format!("io.dockerlens.native-run={run_id}");', live[:start])
        self.assertIn('let image = required("NATIVE_FIXTURE_IMAGE");', live[:start])
        self.assertIn('(&cli_control, false)', live[:start])
        self.assertIn('assert_eq!(cli_control_body["Internal"], false);', live[:start])
        # The old target positive, internal rejection and later recheck stay mandatory.
        self.assertIn('control_response, b"proof-egress",', live[end:])
        self.assertIn('proof_external_blocked(&blocked)', live[end:])
        self.assertIn('"endpoint remains reachable after negative probe"', live[end:])

    def test_only_the_exact_get_inspect_name_is_added_and_rust_negatives_are_independent(self):
        allowed = function("allowed_request")
        binding = 'let proof_cli_control_client = format!("dl-network-{run_id}-proof-cli-control-client");'
        self.assertIn(binding, allowed)
        get = allowed.split('"GET" => {', 1)[1].split('"POST" => {', 1)[0]
        self.assertEqual(get.count('proof_cli_control_client.as_str()'), 1)
        self.assertIn('suffix == format!("containers/{name}/json")', get)
        post = allowed.split('"POST" => {', 1)[1]
        self.assertNotIn('proof_cli_control_client', post)
        self.assertIn('return body.is_none();', allowed)
        self.assertIn('path.strip_prefix(&format!("/v{api_version}/"))', allowed)
        negative = function("internal_cli_control_inspect_admission_requires_exact_context_and_no_body")
        for literal in ('("POST", "1.41", "test")', '("DELETE", "1.41", "test")',
                        '("GET", "1.42", "test")', '("GET", "1.41", "other")',
                        'proof-cli-control-client-extra/json', 'proof-cli-control-client/json?all=true',
                        'containers/create?name=dl-network-test-proof-cli-control-client',
                        'json!(null)', 'json!({})', 'Some(&body)'):
            self.assertIn(literal, negative)
        absent = function("exact_http_absence")
        self.assertIn('command_succeeded && status == b"404"', absent)
        self.assertIn('allowed_request(', SOURCE[SOURCE.index('    fn engine_absent('):
                                                SOURCE.index('    fn remove_owned(')])

    def test_ninth_liability_uses_original_dynamic_cleanup_reserve_and_six_second_cli_owner(self):
        live = function("live_internal_network_blocks_external_egress")
        peers = live[live.index('network_internal_peers'):live.index(CLI_MARKER)]
        self.assertEqual(peers.count('(&control_server, &control, true)'), 1)
        self.assertEqual(peers.count('(&control_client, &control, false)'), 1)
        self.assertEqual(peers.count('(&internal_server, &internal, true)'), 1)
        self.assertEqual(peers.count('(&internal_client, &internal, false)'), 1)
        self.assertIn('resources.containers.push(name.clone());', peers)
        self.assertIn('for (name, is_internal) in [(&cli_control, false), (&cli_internal, true)]', live)
        self.assertIn('(&requests[0], &internal, true)', live)
        self.assertIn('(&requests[1], &control, false)', live)
        self.assertEqual(live.count('resources.networks.push(name.clone());'), 2)
        # Four networks, four original peers, plus exactly one new client.
        outstanding = 4 + 4 + 1
        self.assertIn('outstanding as u64 * 10 + 10 + next_operation_secs', function('proof_required_remaining'))
        self.assertEqual(outstanding * 10 + 10 + 8, 108)
        self.assertLess(107, outstanding * 10 + 10 + 8)
        self.assertIn('self.containers.len() + self.networks.len()', SOURCE)
        self.assertIn('resources.require_budget(8);', function('proof_cli'))
        self.assertIn('bounded_cli(args, "6")', function('proof_cli'))
        self.assertIn('retain_unremoved(&mut self.containers, "container"', SOURCE)
        self.assertIn('into_iter().rev()', function('retain_unremoved'))

    def run_marker(self, lines, status=101, summary=FAILED):
        with tempfile.TemporaryDirectory(prefix="dockerlens-cli-egress-marker-") as directory:
            tools = Path(directory)
            for name in ('timeout', 'grep', 'sed', 'tail', 'date'):
                (tools / name).symlink_to('/usr/bin/' + name)
            cargo = tools / 'cargo'
            cargo.write_text(f'#!{sys.executable}\nimport sys\n'
                             f'if "--list" in sys.argv: print({SELECTED + ": test"!r})\n'
                             f'else:\n print({chr(10).join([*lines, summary])!r})\n raise SystemExit({status})\n')
            cargo.chmod(0o700)
            return subprocess.run(['/bin/bash', str(ROOT / 'scripts/run-exact-native-test.sh'),
                                   'native_network', 'live_internal_network_blocks_external_egress'],
                                  env={'PATH': directory}, capture_output=True, text=True, timeout=4)

    def test_exact_new_marker_supersedes_peers_and_never_claims_target_failure(self):
        result = self.run_marker([PEER_MARKER, CLI_MARKER, 'private-canary /private/socket 10.23.7.9'])
        self.assertEqual((result.returncode, result.stdout), (1, ''))
        self.assertIn(CLI_MARKER + '\n', result.stderr)
        self.assertNotIn(PEER_MARKER, result.stderr)
        self.assertNotIn(TARGET_MARKER, result.stderr)
        self.assertIn(FAILED, result.stderr)
        self.assertNotIn('private-canary', result.stderr)
        result = self.run_marker([PEER_MARKER, CLI_MARKER, TARGET_MARKER])
        self.assertIn(TARGET_MARKER + '\n', result.stderr)
        self.assertNotIn(CLI_MARKER, result.stderr)

    def test_new_marker_near_misses_do_not_leak_or_expand_stage_grammar(self):
        for bad in (CLI_MARKER + '_other', CLI_MARKER + ' private-canary', CLI_MARKER + '\r',
                    CLI_MARKER + '\t', CLI_MARKER + '\x1b[0m', 'prefix ' + CLI_MARKER,
                    CLI_MARKER.replace('cli_control', 'cli-control'),
                    CLI_MARKER.replace('cli_control', 'cli\n_control')):
            with self.subTest(marker=bad):
                result = self.run_marker([PEER_MARKER, bad])
                self.assertEqual((result.returncode, result.stdout), (1, ''))
                self.assertIn(PEER_MARKER + '\n', result.stderr)
                self.assertNotIn(CLI_MARKER, result.stderr)
                self.assertNotIn('private-canary', result.stderr)
        result = self.run_marker([CLI_MARKER], status=0, summary=PASSED)
        self.assertEqual(result.returncode, 0)
        self.assertNotIn(CLI_MARKER, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
