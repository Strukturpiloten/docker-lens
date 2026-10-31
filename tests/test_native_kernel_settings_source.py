"""Finite actor, scope and budget assertions; shell programs only syntax-checked."""

import json
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class KernelSettingsSourceTests(unittest.TestCase):
    def raw(self):
        return (ROOT / "src/native_kernel_settings_tests.rs").read_text()

    def compact(self):
        return re.sub(r"\s+", "", self.raw())

    def script(self, name):
        return re.search(r'const ' + name + r': &str = r#"(.*?)"#;', self.raw(), re.S)[1]

    def test_three_programs_parse_and_literal_request_fits_existing_body_envelope(self):
        for name in ("PARENT", "CHILD", "OBSERVE"):
            result = subprocess.run(["sh", "-n"], input=self.script(name), text=True, capture_output=True, timeout=5, check=False)
            self.assertEqual(result.returncode, 0, name + ": " + result.stderr)
        body = {"Image": "x" * 256, "Cmd": ["sh", "-c", self.script("PARENT"), "dl-ks-Ab12Cd34-true_one-rendered", self.script("CHILD")],
                "Labels": {"io.dockerlens.native-run": "Ab12Cd34"},
                "HostConfig": {"SecurityOpt": ["no-new-privileges:true"], "Sysctls": {"net.ipv4.ip_forward": "1"}}}
        self.assertLessEqual(len(json.dumps(body).encode()), 4096)

    def test_genuine_background_child_exec_has_pid_argv_exe_and_parent_wait_bindings(self):
        parent = self.script("PARENT")
        child = self.script("CHILD")
        observer = self.script("OBSERVE")
        self.assertIn('test "$$" = 1', parent)
        self.assertIn('test "$$" -gt 1', child)
        self.assertIn('(exec /bin/sh -c "$1" "$0-child") &', parent)
        self.assertIn('child=$!', parent)
        self.assertIn('wait "$child"', parent)
        self.assertIn('while :; do sleep 1; done', child)
        for script in (parent, observer):
            self.assertIn('test "/proc/$child/exe" -ef /bin/sh', script)
            self.assertIn('"/proc/$child/cmdline"', script)
            self.assertIn('"/proc/$child/status"' if script == parent else '"/proc/$pid/status"', script)
            self.assertEqual(script.count('printf \'%s\\000\' /bin/sh -c "$1" "$0-child" | cmp "/proc/$child/cmdline" -'), 1)
            self.assertNotRegex(script, r'\btr\s')
        self.assertIn('sample pre', parent)
        self.assertIn('sample post', parent)
        self.assertIn('done </proc/self/status', child)
        for script in (parent, child, observer):
            self.assertIn('NoNewPrivs:', script)
            self.assertIn('/proc/sys/net/ipv4/ip_forward', script)
        self.assertIn('"pre","post","child","bound","root1","rootchild"', self.compact())

    def test_newline_normalization_collides_but_exact_nul_argv_rejects_boundary_drift(self):
        child = self.script("CHILD").encode()
        token = b"dl-ks-Ab12Cd34-false_zero-cli-child"
        self.assertIn(b"\n", child)
        self.assertTrue(child.endswith(b"while :; do sleep 1; done"))
        expected = b"/bin/sh\0-c\0" + child + b"\0" + token + b"\0"
        four_arguments = (b"/bin/sh", b"-c", child, token)
        merged_arguments = (b"/bin/sh", b"-c", child + b"\n" + token)
        exact = b"\0".join(four_arguments) + b"\0"
        merged = b"\0".join(merged_arguments) + b"\0"
        # Model the old tr followed by shell command substitution (trailing LF removal).
        self.assertEqual(exact.replace(b"\0", b"\n").rstrip(b"\n"),
                         merged.replace(b"\0", b"\n").rstrip(b"\n"))
        self.assertEqual(exact, expected)
        for drifted in (merged, exact[:-1], exact + b"\0",
                        b"/bin/sh\0-c\0" + child + b"\n\0" + token + b"\0"):
            with self.subTest(drifted=drifted):
                self.assertNotEqual(drifted, expected)

    def test_only_diagonal_intents_and_explicit_false_requires_zero(self):
        source = self.compact()
        self.assertIn('[("omitted",None),("false_zero",Some(false)),("true_one",Some(true)),]', source)
        for needle in ('"--security-opt".into()', '"no-new-privileges:{flag}"', '"--sysctl".into()',
                       '"net.ipv4.ip_forward={}"', 'SecurityOption::NoNewPrivileges(flag)', 'b"net.ipv4.ip_forward"',
                       '"SecurityOpt":[format!("no-new-privileges:{flag}")]', '"Sysctls":{"net.ipv4.ip_forward":ifflag{"1"}else{"0"}}',
                       'nnp==u8::from(flag)', 'forward==u8::from(flag)', '"scope":"diagonal_omitted_false0_true1_only"'):
            self.assertIn(needle, source)
        self.assertIn('inherited one cannot count as false', self.raw())
        self.assertNotIn('unsupported_inherited', self.raw())
        self.assertIn('FieldState::Missing', self.raw())
        self.assertIn('FieldState::Null', self.raw())
        self.assertIn('FieldState::Empty', self.raw())

    def test_private_per_kind_namespaces_are_bound_to_unchanged_outer_without_mutation(self):
        source = self.compact()
        for needle in ('letouter_ns=outer_namespaces(&run)', 'BTreeSet::from([outer_ns.0])', 'BTreeSet::from([outer_ns.1])',
                       'nets.insert(observed["net_namespace"]', 'pids.insert(observed["pid_namespace"]',
                       'outer_namespaces(&run)==outer_ns', 'namespace(&value["root_net"],"net")==Some(net)',
                       'namespace(&value["root_pidns"],"pid")==Some(pidns)'):
            self.assertIn(needle, source)
        self.assertIn('Some("default"|"bridge")', source)
        for name in ('PARENT', 'CHILD', 'OBSERVE'):
            script = self.script(name)
            self.assertNotRegex(script, r'>\s*/proc/')
            for forbidden in ('sysctl -w', 'nsenter', 'unshare', 'mount ', 'prctl ', 'setpriv '):
                self.assertNotIn(forbidden, script)
        for forbidden in ('--cap-add', '--cap-drop', 'SYS_ADMIN', '--network=host', '--pid=host'):
            self.assertNotIn(forbidden, self.raw())

    def test_actual_one_batch_decoder_checks_security_sysctl_identity_and_availability(self):
        source = self.compact()
        capture = source.split('fnacquisition(', 1)[1].split('#[test]', 1)[0]
        self.assertEqual(capture.count('letcapture=acquire('), 1)
        for needle in ('run.calls.set(calls)', 'run.bytes.set(bytes)'):
            self.assertLess(capture.index(needle), capture.index('letcapture=acquire('))
        for needle in ('checked_add(16)', 'checked_add(BODY_ALLOWANCE)', 'Selector::ContainerIds(ids)',
                       'max_selected_resources:6', 'max_expansions:8', 'max_response_bytes:131072',
                       'Duration::from_secs(46)', 'Duration::from_secs(10)', 'capture.selected_roots().len()==6',
                       'decode_capture(&capture)', 'decoded.containers.len()==6', 'seen.insert(index)',
                       'container.runtime.security_options', 'container.runtime.sysctls', 'Origin::Effective',
                       'Availability::Present', 'security.availability==states[index].0.availability()',
                       'sysctls.availability==states[index].1.availability()', 'entry.key.as_bytes()==b"net.ipv4.ip_forward"',
                       '"byte_scope":"decoded_response_bodies_only"', '"actual_wire_bytes":"not_measured"'):
            self.assertIn(needle, capture)
        self.assertIn('constBODY_ALLOWANCE:usize=512*1024', source)

    def test_borrowed_six_slots_one_cleanup_and_private_protocol_keep_all_original_limits(self):
        source = self.compact()
        for needle in ('run.ids=vec![None;6]', 'run.attempted=vec![false;6]', 'BoundOuterCleanupOwner::bind(&run)',
                       '!run.image_attempted&&run.derived_id.is_none()', 'cleanup_calls==54', 'ordinary_bytes<=MAX_BYTES-CLEANUP_BYTES',
                       'Duration::from_secs(134)', 'Duration::from_secs(46)', 'Duration::from_secs(180)',
                       '"initial_context_acquisition":{"max_requests":16,"max_body_bytes":2097152,"max_elapsed_seconds":15',
                       '"accounting":"separate_existing_bound"', '"capability_admission":[],"catalogue_admission":false'):
            self.assertIn(needle, source)
        self.assertEqual(source.count('cleanup_kernel(&run)'), 1)
        self.assertLess(source.index('terminal_cleanup(&mutrun,&owner,disposition)'), source.index('require_verified_result(result,disposition)'))
        self.assertLess(source.index('require_verified_result(result,disposition)'), source.index('target.publish(&proof)'))
        for forbidden in ('run.cleanup()', 'implDrop', 'run.calls.set(0)', 'run.bytes.set(0)', 'run.deadline='):
            self.assertNotIn(forbidden, source)
        markers = re.findall(r'eprintln!\(\s*"([^"]*)"\s*\)', self.raw())
        self.assertEqual(set(markers), {'DOCKERLENS_NATIVE_CHECK: kernel_settings_' + item
                                      for item in ('context', 'effects', 'capture', 'cleanup', 'proof')})
        self.assertEqual(self.raw().count('eprintln!('), len(markers))
        reader = (ROOT / 'scripts/native_kernel_settings_proof.py').read_text()
        self.assertIn('lambda proof, context: validate_kernel_settings_proof(proof, context, outer_backend=outer_backend)', reader)
        self.assertNotIn('subprocess', reader)
        selected = (ROOT / 'src/reviewed_catalog.rs').read_text()
        for family in ('REVIEWED', 'UPSTREAM'):
            capabilities = selected.split(f'const {family}_CAPABILITIES:', 1)[1].split('];', 1)[0]
            for capability in ('SecurityOptions', 'Sysctls', 'SysctlIpv4Forward'):
                self.assertNotIn('Capability::' + capability + ',', capabilities)

    def test_cleanup_projection_reserves_full_body_and_preserves_actual_output_charge(self):
        source = self.compact()
        inspect = source.split('fnkernel_cleanup_inspect(', 1)[1].split('fnkernel_cleanup_with(', 1)[0]
        self.assertIn('run.request_allowed("GET",&path)', inspect)
        self.assertIn('format!("/v{}/containers/{key}/json",run.api)', inspect)
        self.assertIn('run.timer(true,false)', inspect)
        self.assertIn('/scripts/native_kernel_cleanup.py', inspect)
        self.assertLess(inspect.index('kernel_cleanup_room(run.calls.get(),run.bytes.get())'), inspect.index('run.capture('))
        self.assertLess(inspect.index('run.bytes.set(reserved)'), inspect.index('run.capture('))
        self.assertLess(inspect.index('run.capture('), inspect.index('kernel_cleanup_charge(run.bytes.get(),body_bytes)'))
        self.assertIn('constCLEANUP_INSPECT_BODY_BYTES:usize=65536;', source)
        self.assertIn('constCLEANUP_PROJECTION_ENVELOPE:usize=8192+2048;', source)
        charge = source.split('fnkernel_cleanup_charge(', 1)[1].split('fnkernel_cleanup_inspect(', 1)[0]
        self.assertIn('CLEANUP_INSPECT_BODY_BYTES.checked_sub(actual_body)?', charge)
        self.assertIn('counted_with_reservation.checked_sub(unused)', charge)
        self.assertIn('cleanup_bytes<=54*(8192+2048)', source)
        self.assertNotIn('docker(', inspect)

    def test_cleanup_both_exact_owned_reads_precede_delete_and_two_existing_absence_rounds(self):
        source = self.compact()
        remove = source.split('fnremove_kernel_container(', 1)[1].split('fncleanup_kernel(', 1)[0]
        name_read = remove.index('kernel_cleanup_inspect(run,&run.names[index])')
        name_owned = remove.index('owned(run,&value,index,Some(id))')
        id_read = remove.index('kernel_cleanup_inspect(run,id)')
        id_owned = remove.index('owned(run,&immediate,index,Some(id))')
        deletion = remove.index('run.api("DELETE"')
        self.assertLess(name_read, name_owned)
        self.assertLess(name_owned, id_read)
        self.assertLess(id_read, id_owned)
        self.assertLess(id_owned, deletion)
        self.assertIn('run.inspect(id,true).0==404', remove)
        self.assertIn('run.inspect(&run.names[index],true).0==404', remove)
        self.assertNotIn('run.ids[index]=', remove)
        cleanup = source.split('fncleanup_kernel(', 1)[1].split('#[test]', 1)[0]
        self.assertIn('kernel_cleanup_with(&run.attempted,&run.ids,||', cleanup)
        self.assertIn('for_in0..2', cleanup)
        self.assertIn('run.inspect(id,true).0==404', cleanup)
        self.assertIn('run.inspect(&run.names[index],true).0==404', cleanup)

    def test_unknown_created_id_has_no_inner_io_and_first_panic_outer_handoff_stay_authoritative(self):
        source = self.compact()
        guard = source.split('fnkernel_cleanup_with(', 1)[1].split('fnremove_kernel_container(', 1)[0]
        self.assertIn('attempted.len()!=6||ids.len()!=6', guard)
        self.assertIn('*attempted&&!id.as_deref().is_some_and(identifier)', guard)
        self.assertLess(guard.index('returnCleanupDisposition::OuterTeardownRequired;'), guard.index('inner()'))
        for forbidden in ('inspect(', 'run.api(', 'kernel_cleanup_inspect('):
            self.assertNotIn(forbidden, guard)
        self.assertIn('fnkernel_cleanup_guard_and_body_accounting_controls_are_nonpositive_on_unknowns()', source)
        terminal = source.index('terminal_cleanup(&mutrun,&owner,disposition)')
        self.assertLess(source.index('cleanup_kernel(&run)'), terminal)
        self.assertLess(terminal, source.index('require_verified_result(result,disposition)'))
        lifecycle = (ROOT / 'src/native_lifecycle_tests.rs').read_text()
        self.assertIn('Err(error) => std::panic::resume_unwind(error)', lifecycle)
        self.assertIn('owner.require_teardown()', lifecycle)
        self.assertIn('run.cleaned = true;', lifecycle)



if __name__ == '__main__':
    unittest.main()
