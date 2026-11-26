"""Source and inert byte-binding controls, without running native actors."""

import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NofileSourceTests(unittest.TestCase):
    def raw(self):
        return (ROOT / "src/native_nofile_tests.rs").read_text()

    def compact(self):
        return re.sub(r"\s+", "", self.raw())

    def program(self, name):
        return re.search(r'const ' + name + r': &str =\s*r#"(.*?)"#;', self.raw(), re.S)[1]

    def test_shell_syntax_only_and_complete_literal_request_fits_existing_input_bound(self):
        for name in ("PARENT", "OBSERVE", "BOOTSTRAP"):
            result = subprocess.run(["sh", "-n"], input=self.program(name), text=True,
                                    capture_output=True, timeout=5, check=False)
            self.assertEqual(result.returncode, 0, name + ": " + result.stderr)
        # Independent literal body, including the longest current fixture role.
        body = {"Image": "x" * 256, "Cmd": ["sh", "-c", self.program("BOOTSTRAP"),
                "dl-nf-Ab12Cd34-soft64_hard_unlimited-rendered"],
                "Env": ["DOCKERLENS_NOFILE_PARENT=" + self.program("PARENT"),
                        "DOCKERLENS_NOFILE_WORKER=" + self.program("WORKER")],
                "Labels": {"io.dockerlens.native-run": "Ab12Cd34"},
                "HostConfig": {"Ulimits": [{"Name": "nofile", "Soft": 64, "Hard": -1}]}}
        network = "dl-nf-Ab12Cd34-net-soft64_hard_unlimited"
        body["HostConfig"]["NetworkMode"] = network
        body["NetworkingConfig"] = {"EndpointsConfig": {network: {}}}
        self.assertLessEqual(len(json.dumps(body).encode()), 4096)

    def test_bootstrap_preserves_original_shell_arguments_and_refuses_missing_actors(self):
        token = "dl-nofile-bootstrap"
        # Execute only the bootstrap with an inert program. The canary exercises
        # multiline quoting without interpreting the worker argument as shell.
        worker = 'public canary="literal"\n$(exit 95)'
        env = {"DOCKERLENS_NOFILE_PARENT": 'printf "%s\\0" "$0" "$1"',
               "DOCKERLENS_NOFILE_WORKER": worker}
        command = ["sh", "-c", self.program("BOOTSTRAP"), token]
        result = subprocess.run(command, env=env, capture_output=True, timeout=3, check=False)
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (0, (token + "\0" + worker + "\0").encode(), b""))
        for missing in env:
            result = subprocess.run(command, env={k: v for k, v in env.items() if k != missing},
                                    capture_output=True, timeout=3, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")

    def test_actual_retained_worker_has_binary_exec_binding_and_three_live_barriers(self):
        parent, worker, observer = (self.program(n) for n in ("PARENT", "WORKER", "OBSERVE"))
        self.assertIn('(exec /bin/awk -v "token=$0-child" -f "$d/worker.awk" 3>&-', parent)
        self.assertIn('printf \'%s\' "$1" >"$d/worker.awk";chmod 0400 "$d/worker.awk"', parent)
        self.assertIn('c=$!', parent)
        self.assertIn('wait "$c"', parent)
        exact = 'printf \'%s\\000\' /bin/awk -v "token=$0-child" -f "$d/worker.awk" | cmp "/proc/$c/cmdline" -'
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

    def test_binding_accepts_exact_file_and_argv_and_rejects_each_substitution(self):
        parent = self.program("PARENT").split("b(){\n", 1)[1].split("\n}", 1)[0]
        observer = self.program("OBSERVE").split("site=workerargv\n", 1)[1].split("site=transcript", 1)[0]
        program = 'function sample(){return 0} BEGIN{exit sample()}'
        token = "dl-nofile-control"
        prefix = b"/bin/awk\0-v\0token=dl-nofile-control-child\0"
        inline_rewritten = prefix + program.replace("(", "\0", 1).encode() + b"\0"
        with tempfile.TemporaryDirectory(prefix="dl-nofile-binding-") as directory:
            root = Path(directory)
            proc = root / "proc/2"
            proc.mkdir(parents=True)
            (proc / "exe").symlink_to("/bin/awk")
            cmdline = proc / "cmdline"
            script = root / "worker.awk"
            expected = prefix + b"-f\0" + str(script).encode() + b"\0"
            copied_script = root / "same-bytes"
            copied_script.write_text(program)
            for actor, binding in (("parent", parent), ("observer", observer)):
                for case in ("exact", "inline_rewritten", "altered_program", "symlink"):
                    with self.subTest(actor=actor, case=case):
                        cmdline.write_bytes(inline_rewritten if case == "inline_rewritten" else expected)
                        if case == "symlink":
                            script.symlink_to(copied_script)
                        else:
                            script.write_text(program + "\n" if case == "altered_program" else program)
                        # The actual comparison commands see ordinary scratch files
                        # in place of procfs and no measured worker is started.
                        command = 'd=$2;c=2\n' + binding.replace('/proc/$c/', '$d/proc/$c/')
                        result = subprocess.run(["sh", "-ec", command, token, program, directory],
                                                capture_output=True, timeout=3, check=False)
                        self.assertEqual(result.returncode, 0 if case == "exact" else 1, result.stderr)
                        script.unlink()

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
                       'max_selected_resources:8', 'max_expansions:11', 'max_response_bytes:131072',
                       'Duration::from_secs(46)', 'Duration::from_secs(180)', 'Duration::from_secs(134)',
                       'container_cleanup_calls.get()==8*9', 'network_cleanup_calls==12', 'network_setup_calls==6',
                       'cleanup_calls<=CLEANUP_CALLS', 'slot_calls.iter().sum::<usize>()',
                       '"byte_scope":"decoded_response_bodies_only"', '"actual_wire_bytes":"not_measured"',
                       '"capability_admission":[],"catalogue_admission":false'):
            self.assertIn(needle, source)
        self.assertEqual(source.count('letcapture=acquire_with_shape_detail('), 1)
        self.assertEqual(source.count('cleanup_with_phase(&mutrun)'), 1)
        self.assertNotRegex(self.raw(), r'(?m)^fn cleanup\(')
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
                     '{if*attempted{!id.as_deref().is_some_and(identifier)}else{id.is_some()}})'
                     '||ids.iter().flatten().collect::<BTreeSet<_>>().len()!=ids.iter().flatten().count()')
        self.assertIn(condition, guard)
        self.assertLess(guard.index('returnCleanupDisposition::OuterTeardownRequired;'), guard.index('inner()'))
        self.assertNotIn('inspect(', guard)
        self.assertNotIn('cleanup(', guard)
        self.assertIn('letattempted=run.attempted.clone();letids=run.ids.clone();', source)
        live = source.split('fnlive_nofile_limits_and_effects_match_engine(){', 1)[1].split('#[test]', 1)[0]
        self.assertEqual(live.count('nofile_cleanup_with(&attempted,&ids,||{'), 1)
        callback = live.split('nofile_cleanup_with(&attempted,&ids,||{', 1)[1].split('})', 1)[0]
        self.assertLess(callback.index('entered.set(true)'), callback.index('cleanup_with_phase(&mutrun)'))
        self.assertLess(callback.index('cleanup_with_phase(&mutrun)'),
                        callback.index('networks.cleanup(&run,disposition==CleanupDisposition::VerifiedAbsent)'))
        self.assertIn('first_unverified.set(phase)', callback)
        self.assertLess(live.index('if!networks.bound(&run){returnCleanupDisposition::OuterTeardownRequired;'),
                        live.index('nofile_cleanup_with(&attempted,&ids,||{'))
        self.assertIn('fnnofile_unknown_create_id_never_invokes_inner_cleanup()', source)

        # Independent expected callback control. Exact source predicate and its
        # sole production call are pinned above; the Rust regression also tests
        # the actual helper when main compiles/runs the new module.
        def expected_control(attempted, ids, callback):
            if (len(attempted) != 8 or len(ids) != 8
                    or any((type(bound) is not str or re.fullmatch(r'[0-9a-f]{64}', bound) is None)
                           if tried else bound is not None for tried, bound in zip(attempted, ids))
                    or len([bound for bound in ids if bound is not None])
                       != len({bound for bound in ids if bound is not None})):
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
        for attempted, ids in (([True] * 8, canonical[:7] + [canonical[0]]),
                               ([False] + [True] * 7, canonical)):
            calls = []
            self.assertEqual(expected_control(attempted, ids, lambda: calls.append('cleanup')),
                             'outer_teardown_required')
            self.assertEqual(calls, [])

    def test_guard_disposition_always_reaches_existing_authenticated_terminal_handler(self):
        source = self.compact()
        guarded_call = source.index('nofile_cleanup_with(&attempted,&ids,||{entered.set(true);')
        terminal = source.index('terminal_cleanup(&mutrun,&owner,disposition)')
        verified = source.index('require_verified_result(result,disposition)')
        publish = source.index('target.publish_bounded(&proof,NOFILE_PROOF_MAX_BYTES)')
        self.assertLess(guarded_call, terminal)
        self.assertLess(terminal, verified)
        self.assertLess(verified, publish)
        self.assertEqual(source.count('terminal_cleanup(&mutrun,&owner,disposition)'), 1)
        self.assertNotIn('implDrop', source)
        self.assertNotIn('run.cleanup()', source)

    def test_canonical_source_binds_backend_before_io_without_double_charging(self):
        source = self.compact()
        live = source.split('fnlive_nofile_limits_and_effects_match_engine(){', 1)[1]
        self.assertLess(live.index('letouter_backend=source_outer_backend();'), live.index('ProofTarget::new_for('))
        self.assertEqual(live.count('source_outer_backend()'), 1)
        self.assertEqual(live.count('acquisition(&run,outer_backend,&diagnostics,Some(&networks))'), 1)
        self.assertIn('letfinal_readback_calls=2+outer_backend.snapshot_extra_calls();', live)
        self.assertIn('ordinary_bytes>BODIES+2*outer_backend.snapshot_extra_bytes()', live)
        acquisition = source.split('fnacquisition(', 1)[1].split('#[test]', 1)[0]
        self.assertIn('.checked_add(2+outer_backend.snapshot_extra_calls())', acquisition)
        self.assertIn('.checked_add(2*ORDINARY_CAPTURE_ENVELOPE+outer_backend.snapshot_extra_bytes())', acquisition)
        self.assertEqual(acquisition.count('letcapture=acquire_with_shape_detail('), 1)
        self.assertLess(acquisition.index('run.bytes.set(bytes);'), acquisition.index('letcapture=acquire_with_shape_detail('))
        self.assertNotIn('charge_outer_snapshot(', self.raw())
        harness = (ROOT / 'scripts/native-conformance.sh').read_text()
        self.assertEqual(harness.count('native_nofile live_nofile_limits_and_effects_match_engine'), 1)
        self.assertIn('read_nofile_proof', (ROOT / 'scripts/native-evidence.py').read_text())

    def test_current_packet_uses_measured_three_network_capture_and_scoped_setup_cleanup(self):
        source = self.compact()
        for measured in ('"schema_version":2', '"actual_requests":capture.exchanges().len()',
                         '"actual_expansions":capture.bounds().expansions',
                         '"actual_elapsed_ns":actual_elapsed.as_nanos()',
                         'n.setup_calls', 'n.setup_bytes', 'n.cleanup_calls', 'n.cleanup_bytes',
                         'run.calls.get()-calls', 'run.bytes.get()-bytes'):
            self.assertIn(measured, source)
        for required in ('NetworkSource::External', 'NetworkDriver::Bridge',
                         'body["HostConfig"]["NetworkMode"]=json!(name)',
                         'body["NetworkingConfig"]=json!({"EndpointsConfig":{(name):{}}})',
                         'networks:ifindex<4{vec![]}', 'decoded.networks.len()<=3',
                         'decoded.volumes.is_empty()', 'capture.network_name_fallbacks()',
                         'capture.bounds().expansions==8+n', 'capture.bounds().request_count==10+n',
                         '"endpoint_map_availability":availability_name(availability)',
                         'binding["network_id_availability"]=json!(availability_name(endpoint.availability))',
                         '"active_membership_availability":availability_name(observed.active_endpoints.availability)',
                         '"active_unselected_count":unselected', 'group==0||unselected==0'):
            self.assertIn(required, source)
        scope = source.split('fnnetwork_scope(', 1)[1].split('structNofileNetwork', 1)[0]
        for binding in ('run.run.clone()', 'run.lane.clone()', 'run.candidate.clone()',
                        'run.api.clone()', 'run.socket.clone()', 'run.outer.clone()'):
            self.assertIn(binding, scope)
        health = re.sub(r'\s+', '', (ROOT / 'src/native_health_metadata_tests.rs').read_text())
        ordinary = health.split('fnapi(', 1)[1].split('fnnofile_network_api(', 1)[0]
        self.assertIn('self.request_allowed_with_body(method,path,body)', ordinary)
        bridge = health.split('fnnofile_network_api(', 1)[1].split('fnapi_response(', 1)[0]
        self.assertIn('request.matches(self,cleanup)', bridge)
        self.assertIn('self.api_response(method,path,body,cleanup)', bridge)


    def test_status_observation_is_disabled_elsewhere_and_cleared_before_capture_failures(self):
        shared = (ROOT / "src/native_health_metadata_tests.rs").read_text()
        capture = shared.split("fn capture(", 1)[1].split("fn charge_outer_snapshot", 1)[0]
        self.assertLess(capture.index("observation.begin_capture()"), capture.index("capture_room("))
        self.assertLess(capture.index("original native command must complete successfully"), capture.index("output\n"))
        observed = capture.index("observation.observe_stderr(status, &error)")
        self.assertLess(capture.index('"private stream budget"'), observed)
        self.assertLess(observed, capture.index("original native command must complete successfully"))
        self.assertEqual(capture.count("observation.observe_stderr(status, &error)"), 1)
        self.assertNotIn("observation.observe(status)", capture)
        self.assertIn("nofile_command_observation: None", shared)
        self.assertIn("nofile_command_observation: None", (ROOT / "src/native_lifecycle_default_effect_tests.rs").read_text())
        live = self.raw().split("fn live_nofile_limits_and_effects_match_engine()", 1)[1]
        self.assertLess(live.index("let work_failure"), live.index("observation.reset()"))
        self.assertLess(live.index("observation.reset()"), live.index("nofile_cleanup_with("))
        self.assertLess(live.index("terminal_cleanup("), live.index("if let Some(line) = work_failure"))
        self.assertLess(live.index("if let Some(line) = work_failure"), live.index("if let Some(refusal) = cleanup_refusal"))
        self.assertIn("result.as_ref().err()", re.sub(r"\s+", "", live))

if __name__ == '__main__':
    unittest.main()
