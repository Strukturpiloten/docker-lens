"""Source-only finite actor controls; native programs are NEVER executed here."""

import json
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NofileSourceTests(unittest.TestCase):
    def raw(self):
        return (ROOT / "src/native_nofile_tests.rs").read_text()

    def compact(self):
        return re.sub(r"\s+", "", self.raw())

    def program(self, name):
        return re.search(r'const ' + name + r': &str = r#"(.*?)"#;', self.raw(), re.S)[1]

    def test_shell_syntax_only_and_complete_literal_request_fits_existing_input_bound(self):
        for name in ("PARENT", "OBSERVE"):
            result = subprocess.run(["sh", "-n"], input=self.program(name), text=True,
                                    capture_output=True, timeout=5, check=False)
            self.assertEqual(result.returncode, 0, name + ": " + result.stderr)
        # Independent literal body, including the longest current fixture role.
        body = {"Image": "x" * 256, "Cmd": ["sh", "-c", self.program("PARENT"),
                "dl-nf-Ab12Cd34-soft64_hard_unlimited-rendered", self.program("WORKER")],
                "Labels": {"io.dockerlens.native-run": "Ab12Cd34"},
                "HostConfig": {"Ulimits": [{"Name": "nofile", "Soft": 64, "Hard": -1}]}}
        self.assertLessEqual(len(json.dumps(body).encode()), 4096)

    def test_actual_retained_worker_has_binary_exec_binding_and_three_live_barriers(self):
        parent, worker, observer = (self.program(n) for n in ("PARENT", "WORKER", "OBSERVE"))
        self.assertIn('(exec /bin/awk -v "token=$0-child" "$1" 3>&-', parent)
        self.assertIn('c=$!', parent)
        self.assertIn('wait "$c"', parent)
        exact = 'printf \'%s\\000\' /bin/awk -v "token=$0-child" "$1" | cmp "/proc/$c/cmdline" -'
        for script in (parent, observer):
            self.assertIn(exact, script)
            self.assertIn('test "/proc/$c/exe" -ef /bin/awk', script)
            self.assertNotRegex(script, r'\btr\s')
        self.assertIn('exec 3<>"$d/gate"', parent)
        for phase in ("base", "held", "done"):
            self.assertIn('gate("' + phase + '")', worker)
            self.assertIn('w ' + phase, parent)
        for phase in ("base", "base_repeat", "saturated", "saturated_repeat", "restored"):
            self.assertIn('f ' + phase, parent)
        self.assertLess(parent.index('f saturated_repeat'), parent.index("printf '%s held"))
        self.assertIn('fflush();if((getline g)!=1||g!=token " " tag)exit', worker)

    def test_failure_is_immediate_numeric_emfile_and_reuse_reopens_failed_input(self):
        worker = self.program("WORKER")
        self.assertIn('ERRNO=0;r=(getline v < f);e=ERRNO;', worker)
        self.assertIn('if(r!=1&&(r!=-1||e!=24))exit', worker)
        self.assertIn('if(r==1&&s!="unlimited"&&s<=192)exit', worker)
        self.assertIn('for(i=1;i<=n;i++)if(close(', worker)
        self.assertIn('for(i=1;i<=256;i++)', worker)
        self.assertIn('if((getline v < f)!=1||v!=token " " i||close(f)!=0)exit', worker)
        self.assertIn('sat.keys().copied().eq(0..soft)', self.raw())
        self.assertIn('sat.len() == base.len() + count as usize', self.raw())
        self.assertIn('nodes.insert(', self.raw())
        self.assertNotIn('soft-3', self.compact())
        for unsupported in ('ENFILE', 'ENOSPC', 'permission denied', 'timeout'):
            self.assertNotIn(unsupported, worker)

    def test_four_independent_diagonal_requests_and_truthful_unlimited_dispositions(self):
        source = self.compact()
        for case in ('("soft64_hard128",64,128)', '("soft128_hard128",128,128)',
                     '("soft64_hard_unlimited",64,-1)', '("both_unlimited",-1,-1)'):
            self.assertIn(case, source)
        for needle in ('"--ulimit".into()', 'format!("nofile={soft}:{hard}")',
                       'UlimitValue::Unlimited', 'UlimitValue::Value(nasu64)',
                       '"HostConfig":{"Ulimits":[{"Name":"nofile","Soft":soft,"Hard":hard}]}',
                       '"exact_finite_emfile"', '"finite_kernel_normalization"',
                       '"exact_hard_unlimited_finite_soft_emfile"', '"exact_both_unlimited_bounded_success"',
                       '"specific_nofile_start_refusal"'):
            self.assertIn(needle, source)
        self.assertIn('"error setting rlimit type 7: operation not permitted"', self.raw())
        self.assertIn('reported["message"] == error', self.raw())
        self.assertIn('after["State"] == current["State"]', self.raw())
        self.assertIn('run.request_allowed("POST", &path)', self.raw())
        self.assertIn('/scripts/native-unix-http.py', self.raw())
        self.assertIn('let message: String = serde_json::from_str(literal)', self.raw())

    def test_original_budgets_one_acquisition_and_once_only_unknown_id_cleanup(self):
        source = self.compact()
        for needle in ('run.ids=vec![None;8]', 'run.attempted=vec![false;8]',
                       'BoundOuterCleanupOwner::bind(&run)', 'checked_add(REQUESTS)', 'checked_add(BODIES)',
                       'max_selected_resources:8', 'max_expansions:10', 'max_response_bytes:131072',
                       'Duration::from_secs(46)', 'Duration::from_secs(180)', 'Duration::from_secs(134)',
                       'cleanup_calls==8*9', 'slot_calls.iter().sum::<usize>()',
                       '"byte_scope":"decoded_response_bodies_only"', '"actual_wire_bytes":"not_measured"',
                       '"capability_admission":[],"catalogue_admission":false'):
            self.assertIn(needle, source)
        self.assertEqual(source.count('letcapture=acquire('), 1)
        self.assertEqual(source.count('cleanup(&mutrun)'), 1)
        self.assertNotIn('fncleanup(', source)
        self.assertIn('terminal_cleanup(&mutrun,&owner,disposition)', source)
        self.assertLess(source.index('require_verified_result(result,disposition)'), source.index('target.publish_bounded(&proof,NOFILE_PROOF_MAX_BYTES)'))
        self.assertIn('constNOFILE_PROOF_MAX_BYTES:usize=512*1024', source)
        for forbidden in ('--cap-add', '--cap-drop', 'SYS_ADMIN', 'sysctl -w', 'nsenter', 'unshare',
                          'implDrop', 'run.calls.set(0)', 'run.bytes.set(0)', 'run.deadline='):
            self.assertNotIn(forbidden, self.raw())

    def test_unknown_attempted_id_guard_never_invokes_cleanup_and_bound_ids_allow_it(self):
        source = self.compact()
        guard = source.split('fnnofile_cleanup_with(', 1)[1].split('#[test]', 1)[0]
        condition = ('attempted.len()!=8||ids.len()!=8||attempted.iter().zip(ids).any(|(attempted,id)|'
                     '*attempted&&!id.as_deref().is_some_and(identifier))')
        self.assertIn(condition, guard)
        self.assertLess(guard.index('returnCleanupDisposition::OuterTeardownRequired;'), guard.index('inner()'))
        self.assertNotIn('inspect(', guard)
        self.assertNotIn('cleanup(', guard)
        self.assertIn('letattempted=run.attempted.clone();letids=run.ids.clone();', source)
        guarded_call = 'nofile_cleanup_with(&attempted,&ids,||cleanup(&mutrun))'
        self.assertEqual(source.count(guarded_call), 1)
        self.assertIn('fnnofile_unknown_create_id_never_invokes_inner_cleanup()', source)

        # Independent expected callback control. Exact source predicate and its
        # sole production call are pinned above; the Rust regression also tests
        # the actual helper when main compiles/runs the new module.
        def expected_control(attempted, ids, callback):
            if (len(attempted) != 8 or len(ids) != 8
                    or any(tried and (type(bound) is not str or re.fullmatch(r'[0-9a-f]{64}', bound) is None)
                           for tried, bound in zip(attempted, ids))):
                return 'outer_teardown_required'
            return callback()

        canonical = [f'{i:064x}' for i in range(1, 9)]
        for invalid in (None, 'malformed', 'a' * 63, 'A' * 64):
            calls = []
            ids = canonical.copy()
            ids[3] = invalid
            self.assertEqual(expected_control([True] * 8, ids, lambda: calls.append('cleanup')),
                             'outer_teardown_required')
            self.assertEqual(calls, [])
        calls = []
        self.assertEqual(expected_control([True] * 8, canonical, lambda: calls.append('cleanup') or 'verified_absent'),
                         'verified_absent')
        self.assertEqual(calls, ['cleanup'])

    def test_guard_disposition_always_reaches_existing_authenticated_terminal_handler(self):
        source = self.compact()
        guarded_call = source.index('nofile_cleanup_with(&attempted,&ids,||cleanup(&mutrun))')
        terminal = source.index('terminal_cleanup(&mutrun,&owner,disposition)')
        verified = source.index('require_verified_result(result,disposition)')
        publish = source.index('target.publish_bounded(&proof,NOFILE_PROOF_MAX_BYTES)')
        self.assertLess(guarded_call, terminal)
        self.assertLess(terminal, verified)
        self.assertLess(verified, publish)
        self.assertEqual(source.count('terminal_cleanup(&mutrun,&owner,disposition)'), 1)
        self.assertNotIn('implDrop', source)
        self.assertNotIn('run.cleanup()', source)


if __name__ == '__main__':
    unittest.main()
