"""Source-only actor/ownership/budget controls; no container execution."""

import json
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SupplementaryGroupsSourceTests(unittest.TestCase):
    def raw(self):
        return (ROOT / "src/native_supplementary_groups_tests.rs").read_text()

    def source(self):
        return re.sub(r"\s+", " ", self.raw())

    def script(self, name):
        return re.search(r'const ' + name + r': &str = r#"(.*?)"#;', self.raw(), re.S)[1]

    def test_all_three_shell_programs_parse_without_execution(self):
        for name in ("GROUP_PROCESS", "PREPARE", "COLLECT"):
            script = self.script(name)
            result = subprocess.run(["sh", "-n"], input=script, text=True, capture_output=True, timeout=5, check=False)
            self.assertEqual(result.returncode, 0, name + ": " + result.stderr)
        # The original native HTTP helper limits request bodies to 4096 bytes.
        literal = {"Image": "x" * 256, "User": "12345:3456", "Cmd": ["sh", "-c", self.script("GROUP_PROCESS")],
                   "Labels": {"io.dockerlens.native-run": "Ab12Cd34"}, "HostConfig": {"GroupAdd": ["23456", "34567"]}}
        self.assertLess(len(json.dumps(literal).encode()), 4096)

    def test_nonroot_pid1_is_the_only_permission_writer(self):
        worker = self.script("GROUP_PROCESS")
        self.assertIn('test "$$" = 1', worker)
        self.assertIn('test "$(type printf)" = \'printf is a shell builtin\'', worker)
        self.assertIn('done </proc/1/status', worker)
        self.assertIn('facts pre', worker)
        self.assertIn('facts post', worker)
        for path, canary in (("first", "sg-worker-one"), ("second", "sg-worker-two")):
            self.assertIn("if { printf '%s' " + canary + " >/dl-sg/" + path + "; }", worker)
        self.assertIn('Permission denied', worker)
        self.assertIn('while :; do sleep 1; done', worker)
        self.assertNotIn('23456', worker)
        self.assertNotIn('34567', worker)
        self.assertNotIn('chown', worker)
        self.assertNotIn('chmod', worker)
        self.assertNotIn('docker', worker)
        self.assertNotIn('failure=$(', worker)
        source = self.source()
        self.assertEqual(source.count('"--user".into(), "0:0".into()'), 2)
        self.assertIn('"--user".into(), "12345:3456".into()', source)
        self.assertIn('record["pid"] == ["1"]', source)
        for marker in ('"pre", "post", "root"', '["12345"; 4]', '["3456"; 4]', '["0000000000000000"]'):
            self.assertIn(marker, source)

    def test_root_only_sets_metadata_and_independently_reads_the_worker_results(self):
        prepare = self.script("PREPARE")
        collect = self.script("COLLECT")
        self.assertIn('test "$(id -u)" = 0; test "$(id -g)" = 0', prepare)
        self.assertIn('chown 0:23456 /dl-sg/first', prepare)
        self.assertIn('chown 0:34567 /dl-sg/second', prepare)
        self.assertIn('chmod 0660 /dl-sg/first /dl-sg/second', prepare)
        for path, gid in (("first", 23456), ("second", 34567)):
            assertion = f'test "$(stat -c %u:%g:%a /dl-sg/{path})" = 0:{gid}:660'
            self.assertIn(assertion, prepare)
            self.assertIn(assertion, collect)
        self.assertIn('done </proc/1/status', collect)
        self.assertIn('cat /tmp/dl-sg-report', collect)
        self.assertIn('$(cat /dl-sg/first)', collect)
        self.assertIn('$(cat /dl-sg/second)', collect)
        self.assertNotIn('>/dl-sg/first', collect)
        self.assertNotIn('>/dl-sg/second', collect)
        self.assertNotIn('sg-worker-one', prepare)
        self.assertNotIn('sg-worker-two', prepare)
        self.assertIn('test ! -L /dl-sg', prepare)
        self.assertIn('"root_exec_scope":"setup_and_readback_only"', self.source())

    def test_native_groupadd_omission_and_optional_primary_group_remain_distinct(self):
        source = self.source()
        self.assertIn('[ ("omitted", &[]), ("one", &[23456]), ("pair", &[23456, 34567]), ]', source)
        self.assertIn('"--group-add".into(), group.to_string()', source)
        self.assertIn('if !groups.is_empty()', source)
        for value in ('GroupState::Missing', 'GroupState::Null', 'GroupState::Empty', 'GroupState::Present'):
            self.assertIn(value, source)
        self.assertIn('filter(|group| *group != 3456)', source)
        self.assertIn('extra == CASES[index / 2].1', source)
        self.assertIn('"primary_gid_in_groups":kernel.contains(&3456)', source)
        self.assertNotIn('assert!(kernel.contains(&3456)', source)

    def test_single_charged_capture_checks_real_decoded_identity_availability_and_groups(self):
        source = self.source()
        capture = source.split('fn acquisition(', 1)[1].split('#[test]', 1)[0]
        self.assertEqual(capture.count('let capture = acquire('), 1)
        for needle in ('run.calls.set(calls)', 'run.bytes.set(bytes)'):
            self.assertLess(capture.index(needle), capture.index('let capture = acquire('))
        for needle in ('checked_add(16)', 'checked_add(BODY_ALLOWANCE)', 'Selector::ContainerIds(ids)',
                       'max_selected_resources: 6', 'max_expansions: 8', 'Duration::from_secs(46)', 'Duration::from_secs(10)',
                       'capture.selected_roots().len() == 6', 'decoded.containers.len() == 6', 'decode_capture(&capture)',
                       'container.runtime.supplementary_groups', 'groups.availability == states[index].availability()',
                       'Origin::Effective', 'Origin::RuntimeAssigned', 'seen.insert(index)', 'container .user .value()',
                       'b"12345:3456"', 'decoded.version.daemon.observation_id == capture.observation_id()',
                       '"byte_scope":"decoded_response_bodies_only"', '"actual_wire_bytes":"not_measured"'):
            self.assertIn(needle, capture)
        self.assertIn('const BODY_ALLOWANCE: usize = 512 * 1024', source)
        self.assertIn('"rootless_observed"', capture)
        self.assertIn('"unknown_with_independent_rootful_context"', capture)

    def test_contract_distinguishes_integrated_source_from_native_qualification(self):
        contract = (ROOT / 'docs/native-supplementary-groups-contract.md').read_text()
        normalized = ' '.join(contract.split())
        self.assertIn('independently selected backend', normalized)
        for marker in ('supplementary-groups-v1', 'closed unadmitted observation'):
            self.assertIn(marker, normalized)
        for requirement in (r'\bmandatory\b[^.]*\binvocation 25\b',
                            r'\bstrict\b[^.]*\breader\b[^.]*\bwithout\b[^.]*\bemission\b',
                            r'\bsynthetic\b[^.]*\bnot\b[^.]*\bnative qualification\b',
                            r'\bexact-final-candidate\b[^.]*\b26-invocation\b[^.]*\bfour-lane\b',
                            r'\bno\b[^.]*\breviewed catalogue admission\b',
                            r'\bno\b[^.]*\bnative compatibility\b'):
            self.assertRegex(normalized, requirement)
        self.assertNotRegex(normalized, r'\bprepared, unregistered\b')

    def test_exact_six_slot_once_cleanup_and_original_budgets_guard_private_publication(self):
        source = self.source()
        for needle in ('run.ids = vec![None; 6]', 'run.attempted = vec![false; 6]',
                       'BoundOuterCleanupOwner::bind(&run)', 'cleanup_calls == 54',
                       'ordinary_bytes <= MAX_BYTES - CLEANUP_BYTES', 'Duration::from_secs(180)',
                       '"accounting":"separate_existing_bound"', '!run.image_attempted && run.derived_id.is_none()'):
            self.assertIn(needle, source)
        self.assertEqual(source.count('cleanup(&mut run)'), 1)
        self.assertNotIn('run.cleanup()', source)
        self.assertNotIn('impl Drop', source)
        self.assertNotIn('run.calls.set(0)', source)
        self.assertNotIn('run.bytes.set(0)', source)
        self.assertNotIn('run.deadline =', source)
        terminal = source.index('terminal_cleanup(&mut run, &owner, disposition)')
        verified = source.index('require_verified_result(result, disposition)')
        self.assertLess(terminal, verified)
        self.assertLess(verified, source.index('target.publish(&proof)'))
        self.assertIn('"capability_admission":[],"catalogue_admission":false', source)
        markers = re.findall(r'eprintln!\("([^"]*)"\)', source)
        self.assertEqual(set(markers), {'DOCKERLENS_NATIVE_CHECK: supplementary_groups_' + item
                                      for item in ('context', 'effects', 'capture', 'cleanup', 'proof')})
        self.assertEqual(source.count('eprintln!('), len(markers))
        selected = (ROOT / 'src/reviewed_catalog.rs').read_text()
        for family in ('REVIEWED', 'UPSTREAM'):
            self.assertNotIn('Capability::SupplementaryGroups,', selected.split(f'const {family}_CAPABILITIES:', 1)[1].split('];', 1)[0])


if __name__ == '__main__':
    unittest.main()
