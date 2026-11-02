"""Independent matching refusals over real production bodies and a virtual kernel."""
import ast
from contextlib import ExitStack
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from native_pids_matching_support import normalized_matching_metadata
import test_native_pids_discovery as legacy
from test_native_pids_discovery import SyntheticSource, boundary as b, locator as l, discovery as d

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = '''mleaseentry mrecord mprocbind mstatussame mscope mcallback mcallbackpure mselect
mfinishstate mfinishroles mfinishseen mrollback mprocpid mprocstartvalue mprocpidfd mprocdir
mprocfs mprocstart mproccgroup mprocwithin mprocroot mprocns mprocstatus mprocidentity
mproccheck mcheckbudget mchecklive mcheckstart mcheckcgroup mcheckstatus mcheckreopen
mcheckidentity mcheckclose mtimeopen mtimematch mtimelive mtimeregister mctimeopen
mctimematch mctimeclose mnamespaceactive mnamespacedepth mnamespacereserve mnamespaceparent
mnamespaceadopt mnamespacecycle mnamespaceobjects mnamespacevector mstatdelimiter mstatstate
mstatstart mcgrouprecord mstatusfields mstatuspid mstatustgid mstatusuid mstatusnspid mfdmount
mstatusnstgid mprivate mambiguous mnomatch mbudgettime mbudgetreads mbudgetbytes mbudgetfds
mbudgetopens mreadopen mreadfs mreadseek mreadsyscall mreadcap mreadclose'''.split()


def method(source, owner, name):
    body = ast.parse(source).body
    if owner:
        body = next(n.body for n in body if isinstance(n, ast.ClassDef) and n.name == owner)
    return next(n for n in body if isinstance(n, ast.FunctionDef) and n.name == name)


def trusted_consume(before, daemon_ns):
    runtime = method((ROOT / 'scripts/native_pids_locator.py').read_text(), 'RuntimeLocator', 'locate_batch')
    consume = next(n for n in ast.walk(runtime) if isinstance(n, ast.FunctionDef) and n.name == 'consume')
    namespace = dict(l.__dict__, discovery=d, before=before, daemon_ns=daemon_ns, matched=set())
    exec(compile(ast.fix_missing_locations(ast.Module(body=[consume], type_ignores=[])), '<trusted WORKERS callback>', 'exec'), namespace)
    return namespace['consume']


class MatchingTests(unittest.TestCase):
    def test_static_union_and_unchanged_record_bounds(self):
        self.assertEqual(list(b.MATCHING_SITES), EXPECTED)
        self.assertEqual(len(set(EXPECTED)), 73)
        self.assertEqual(len(l.LOCATE_STAGES), 90)
        maximum = max(len(f'DOCKERLENS_NATIVE_PIDS_LOCATE: stage={s} category={c}\n'.encode())
            for s in l.LOCATE_STAGES for c in l.LOCATE_CATEGORIES)
        projected = max(len(('DOCKERLENS_NATIVE_PIDS_MEASUREMENT_REFUSAL: code=pids-eof'
            f' caller=locate_batch slot=none phase=none source_stage={s} source_category={c}\n').encode())
            for s in l.LOCATE_STAGES for c in l.LOCATE_CATEGORIES)
        self.assertEqual((maximum, projected), (91, 173))
        self.assertLessEqual(maximum - 1, 111)

    def test_frozen_pre_matching_bodies_preserve_every_original_expression_and_order(self):
        raw = (ROOT / 'tests/fixtures/native_pids_pre_matching_methods.json').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), '0ad46dd0778ce65c2bbb49e9e69b172eaff6064bb8599ffda8137b28d271d9a2')
        baseline = json.loads(raw)
        self.assertEqual(baseline['source_commit'], 'ec58b844a46c881ea175bccae85a049f609b43c1')
        for record in baseline['methods'].values():
            with self.subTest(path=record['path'], owner=record['owner'], name=record['name']):
                self.assertEqual(hashlib.sha256(record['source'].encode()).hexdigest(), record['sha256'])
                original = ast.parse(record['source']).body[0]
                current = normalized_matching_metadata(method((ROOT / record['path']).read_text(), record['owner'], record['name']))
                # Only the fixed newly optional parameter may be erased. Existing
                # read/read_fd metadata plumbing remains part of the frozen body.
                if ast.dump(current.args) != ast.dump(original.args):
                    self.assertEqual(current.args.args[-1].arg, 'observer')
                    self.assertEqual(ast.dump(current.args.defaults[-1]), 'Constant(value=None)')
                    current.args.args.pop(); current.args.defaults.pop()
                self.assertEqual(ast.dump(current), ast.dump(original))

    def test_ast_erasure_rejects_unknown_sites_callees_observers_and_cleanup(self):
        original = method((ROOT / 'scripts/native_pids_boundary.py').read_text(), 'LinuxSource', 'read')
        for mutation in ('site', 'callee', 'observer', 'cleanup'):
            node = ast.parse(ast.unparse(original)).body[0]
            calls = list(n for n in ast.walk(node) if isinstance(n, ast.Call))
            if mutation == 'site':
                next(n for n in calls if ast.unparse(n.func) == 'matching_scope').args[1] = ast.Constant('PRIVATE')
            elif mutation == 'callee':
                next(n for n in calls if ast.unparse(n.func) == 'matching_call').args[1] = ast.Name(id='other', ctx=ast.Load())
            elif mutation == 'observer':
                next(n for n in calls if ast.unparse(n.func) == 'matching_call').args[0] = ast.Name(id='other', ctx=ast.Load())
            else:
                next(n for n in calls if ast.unparse(n.func) == 'matching_scope').keywords.append(ast.keyword(arg='cleanup', value=ast.Constant(True)))
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                normalized_matching_metadata(node)

    def workers(self, fixture):
        before = {slot: (70 + index, 'unchanged') for index, slot in enumerate(l.ORDER)}
        return trusted_consume(before, (20, 110))

    def test_actual_trusted_callback_none_and_active_have_identical_source_and_custody_ledgers(self):
        results = []
        for active in (False, True):
            fixture = SyntheticSource(workers=True)
            observed = []
            with fixture.environment():
                transfer = d.discover(fixture.source, fixture.outer, d.Mode.WORKERS, self.workers(fixture),
                    **({'failure_site': observed.append} if active else {}))
                self.assertEqual(len(transfer.selections), 6)
                transfer.close()
            budget = fixture.source.budget
            results.append((fixture.trace, fixture.source.owned, tuple(getattr(budget, name) for name in
                ('reads', 'bytes', 'fds', 'opens', 'peak_fds', 'frames', 'output', 'deadline_ns'))))
            self.assertEqual(observed, [])
            self.assertEqual(fixture.source.owned, fixture.baseline)
        self.assertEqual(results[0], results[1])

    def test_actual_trusted_callback_independent_namespace_time_and_private_init_counterexamples(self):
        for site in ('mnamespacevector', 'mtimematch', 'mprivate', 'mnomatch', 'mambiguous'):
            fixture = SyntheticSource(workers=True)
            if site == 'mnamespacevector':
                fixture.parents[200] = 0
            elif site == 'mprivate':
                fixture.processes[200][3] = (200, 70, 2)
            elif site == 'mnomatch':
                fixture.processes[200][3] = (200, 99, 1)
            elif site == 'mambiguous':
                fixture.processes[201][3] = (201, 70, 1)
            original_open = fixture.open
            def opened(name, flags, *, dir_fd=None):
                fd = original_open(name, flags, dir_fd=dir_fd)
                if site == 'mtimematch' and name == 'ns/time':
                    fixture.objects[fd] = 'namespace', ('time', 99)
                return fd
            observed = []
            with self.subTest(site=site), fixture.environment(), patch.object(b.os, 'open', opened):
                with self.assertRaises(b.Refusal) as caught:
                    d.discover(fixture.source, fixture.outer, d.Mode.WORKERS, self.workers(fixture), failure_site=observed.append)
                self.assertIs(type(caught.exception), l.LocatorRefusal if site in ('mnomatch', 'mambiguous') else b.Refusal)
                self.assertEqual(observed, [site])
                self.assertEqual(fixture.source.owned, fixture.baseline)

    def assert_site(self, observer, site, function, error_type=b.Refusal):
        with self.assertRaises(error_type) as caught:
            function()
        self.assertEqual(b.matching_site(observer), site)
        return caught.exception

    def test_original_parser_predicates_have_distinct_refusals(self):
        good = b'Pid: 110\nTgid: 110\nUid: 1 1 1 1\nNSpid: 110 2\nNStgid: 110 2\n'
        cases = [('mstatdelimiter', lambda o: b.start_from_stat(b'bad', 110, observer=o)),
            ('mstatstate', lambda o: b.start_from_stat(b'110 (x) Z ' + b'0 ' * 19, 110, observer=o)),
            ('mstatstart', lambda o: b.start_from_stat(b'110 (x) S ' + b'0 ' * 18 + b'x', 110, observer=o)),
            ('mcgrouprecord', lambda o: b.cgroup_path(b'0::/../bad\n', observer=o)),
            ('mstatusfields', lambda o: b.process_status(good + b'Pid: 110\n', 110, observer=o)),
            ('mstatuspid', lambda o: b.process_status(good, 111, observer=o)),
            ('mstatustgid', lambda o: b.process_status(good.replace(b'Tgid: 110', b'Tgid: 111'), 110, leader=True, observer=o)),
            ('mstatusuid', lambda o: b.process_status(good.replace(b'Uid: 1 1 1 1', b'Uid: 1'), 110, observer=o)),
            ('mstatusnspid', lambda o: b.process_status(good.replace(b'NSpid: 110 2', b'NSpid: 110 0'), 110, observer=o)),
            ('mstatusnstgid', lambda o: l.status_vectors(good.replace(b'NStgid: 110 2', b'NStgid: 110 3'), 110, observer=o))]
        for site, call in cases:
            with self.subTest(site=site):
                observer = b.matching_observation()
                self.assert_site(observer, site, lambda: call(observer))

    def test_budget_and_read_failures_preserve_charges_and_work_exception(self):
        for field, initial, site, call in [('clock', None, 'mbudgettime', 'check'),
                ('reads', 65536, 'mbudgetreads', 'read'), ('bytes', b.SOURCE_BYTES, 'mbudgetbytes', 'read'),
                ('fds', 256, 'mbudgetfds', 'fd'), ('opens', 32768, 'mbudgetopens', 'fd')]:
            budget = b.Budget(180_000_000_001, lambda: 1)
            if field == 'clock':
                budget.clock = lambda: budget.work_ns
            else:
                setattr(budget, field, initial)
            observer = b.matching_observation()
            with self.subTest(site=site):
                self.assert_site(observer, site, lambda: getattr(budget, call)(*([1] if call == 'read' else []), observer=observer))
        for site in ('mreadopen', 'mreadfs', 'mreadseek', 'mreadsyscall', 'mreadcap', 'mreadclose', 'mfdmount'):
            fixture = SyntheticSource()
            observer = b.matching_observation()
            work = RuntimeError('PRIVATE_WORK')
            with self.subTest(site=site), fixture.environment(), ExitStack() as stack:
                if site == 'mreadopen':
                    stack.enter_context(patch.object(b.os, 'open', side_effect=work))
                elif site == 'mreadfs':
                    stack.enter_context(patch.object(b, 'fs_magic', return_value=0))
                elif site == 'mreadseek':
                    stack.enter_context(patch.object(b.os, 'lseek', side_effect=work))
                elif site == 'mreadsyscall':
                    fixture.read_error = work
                elif site == 'mreadclose':
                    fixture.fail_close = lambda fd: True
                elif site == 'mfdmount':
                    stack.enter_context(patch.object(fixture, 'body', return_value=b'mnt_id: 0\n'))
                if site == 'mfdmount':
                    call = lambda: fixture.source.fd_mount_id(fixture.root, observer=observer)
                else:
                    call = lambda: fixture.source.read(fixture.source.proc, '110/stat', 1 if site == 'mreadcap' else 1024, observer=observer)
                    # Numeric directory is not needed for the existing leaf reader.
                    original_open = fixture.open
                    def opened(name, flags, *, dir_fd=None):
                        if name == '110/stat':
                            return fixture.allocate('file', ('procdir', 110, 'stat'))
                        return original_open(name, flags, dir_fd=dir_fd)
                    if site != 'mreadopen':
                        stack.enter_context(patch.object(b.os, 'open', opened))
                error = self.assert_site(observer, site, call, RuntimeError if site in ('mreadopen', 'mreadseek', 'mreadsyscall') else OSError if site == 'mreadclose' else b.Refusal)
                if site in ('mreadopen', 'mreadseek', 'mreadsyscall'):
                    self.assertIs(error, work)
                fixture.fail_close = None
                fixture.source.release_since(fixture.baseline)
                self.assertEqual(fixture.source.owned, fixture.baseline)

    def test_discover_fresh_status_guards_deliver_the_actual_escape_after_cleanup(self):
        fields = ('reads', 'bytes', 'fds', 'opens', 'peak_fds', 'output', 'frames')
        for fault in ('cap', 'time', 'reads', 'bytes', 'fds', 'opens'):
            comparisons = []
            for active in (False, True):
                fixture = SyntheticSource()
                source, budget = fixture.source, fixture.source.budget
                state = {'acquired': False, 'triggered': False}
                observed, actual_errors, guard_errors, events = [], [], [], []
                original_process, original_read_fd, original_open = source.process, source.read_fd, source.open
                original_require, original_startup, original_body = b.require, b.startup_require, fixture.body
                def record_guard(function, *args):
                    try:
                        return function(*args)
                    except b.Refusal as error:
                        guard_errors.append(error)
                        raise
                def process(pid, start, observer=None):
                    value = b.matching_call(observer, original_process, pid, start)
                    state['acquired'] = True
                    events.append(('process_acquired', pid))
                    return value
                def trigger():
                    self.assertTrue(state['acquired'])
                    self.assertFalse(state['triggered'])
                    state['triggered'] = True
                    if fault == 'time':
                        budget.clock = lambda: budget.work_ns
                    elif fault == 'reads':
                        budget.reads = 65536
                    elif fault == 'bytes':
                        budget.bytes = b.SOURCE_BYTES
                    elif fault == 'fds':
                        budget.fds = 256
                    elif fault == 'opens':
                        budget.opens = 32768
                    state['before'] = tuple(getattr(budget, field) for field in fields)
                    state['trace_start'] = len(fixture.trace)
                def open_file(name, parent=None, directory=False, magic=False, observer=None):
                    if state['acquired'] and name == 'status' and fault in ('fds', 'opens'):
                        # The original FD reservation necessarily precedes open;
                        # force only the fresh read after actual process custody.
                        trigger()
                    try:
                        return b.matching_call(observer, original_open, name, parent, directory=directory, magic=magic)
                    except b.Refusal as error:
                        actual_errors.append(error)
                        raise
                def read_fd(fd, maximum, observer=None):
                    if state['acquired'] and fixture.objects[fd] == ('file', ('procdir', 110, 'status')):
                        self.assertEqual(maximum, 4096)
                        trigger()  # original open and filesystem check already succeeded
                        state['fresh_fd'] = fd
                    try:
                        return b.matching_call(observer, original_read_fd, fd, maximum)
                    except b.Refusal as error:
                        actual_errors.append(error)
                        raise
                def body(fd):
                    if fault == 'cap' and state.get('fresh_fd') == fd:
                        return b'x' * 4097
                    return original_body(fd)
                with self.subTest(fault=fault, active=active), fixture.environment(), patch.object(source, 'process', process), \
                        patch.object(source, 'open', open_file), patch.object(source, 'read_fd', read_fd), \
                        patch.object(fixture, 'body', body), \
                        patch.object(b, 'require', side_effect=lambda value: record_guard(original_require, value)), \
                        patch.object(b, 'startup_require', side_effect=lambda site, value: record_guard(original_startup, site, value)):
                    with self.assertRaises(b.Refusal) as escaped:
                        d.discover(source, fixture.outer, d.Mode.PEER,
                            lambda lease: legacy.DiscoveryTests().consume_peer(lease),
                            **({'failure_site': observed.append} if active else {}))
                    self.assertTrue(state['triggered'])
                    self.assertEqual(events, [('process_acquired', 110)])
                    self.assertEqual(len(guard_errors), 1)
                    self.assertIs(escaped.exception, guard_errors[0])
                    self.assertIs(escaped.exception, actual_errors[0])
                    self.assertIs(type(escaped.exception), b.Refusal)
                    self.assertEqual(observed, ['mreadcap' if fault == 'cap' else 'mbudget' + fault] if active else [])
                    self.assertEqual(source.owned, fixture.baseline)
                    self.assertEqual(source.process_times, {})
                    after = tuple(getattr(budget, field) for field in fields)
                    reads = [event for event in fixture.trace[state['trace_start']:] if event[0] == 'read']
                    before = state['before']
                    if fault == 'cap':
                        self.assertEqual([event[2] for event in reads], [1024, 1024, 1024, 1024, 1])
                        self.assertEqual(after[:2], (before[0] + 5, before[1] + 4097))
                    else:
                        self.assertEqual(reads, [])
                        if fault == 'time':
                            self.assertEqual(after[:2], before[:2])
                        elif fault in ('reads', 'bytes'):
                            self.assertEqual(after[:2], (before[0] + 1, before[1] + 1024))
                        else:
                            self.assertEqual(after[:2], before[:2])
                            self.assertEqual(after[3], before[3] + 1)
                    closed = [event[1] for event in fixture.trace[state['trace_start']:] if event[0] == 'close']
                    self.assertEqual(len(closed), len(set(closed)))
                    self.assertTrue(set(closed).isdisjoint(fixture.baseline))
                    self.assertEqual(after[2], before[2] + (1 if fault in ('fds', 'opens') else 0) - len(closed))
                    self.assertEqual(after[3], before[3] + (1 if fault in ('fds', 'opens') else 0))
                    comparisons.append((fixture.trace, before, after))
                    source.release_since(frozenset())
                    self.assertEqual(source.owned, set())
                if active:
                    self.assertEqual(comparisons[0], comparisons[1])

    def test_fresh_status_guard_keeps_an_actually_superseding_leaf_cleanup_exception(self):
        fixture = SyntheticSource()
        source, budget = fixture.source, fixture.source.budget
        original_process, original_read_fd, original_body, original_close = source.process, source.read_fd, fixture.body, source.close_fd
        state = {'acquired': False, 'fresh_fd': None}
        observed, work_errors = [], []
        cleanup = RuntimeError('PRIVATE_FRESH_STATUS_CLOSE')
        def process(pid, start, observer=None):
            value = b.matching_call(observer, original_process, pid, start)
            state['acquired'] = True
            return value
        def read_fd(fd, maximum, observer=None):
            if state['acquired'] and fixture.objects[fd] == ('file', ('procdir', 110, 'status')):
                state['fresh_fd'] = fd
            try:
                return b.matching_call(observer, original_read_fd, fd, maximum)
            except b.Refusal as error:
                work_errors.append(error)
                raise
        def body(fd):
            return b'x' * 4097 if state['fresh_fd'] == fd else original_body(fd)
        def close(fd):
            original_close(fd)
            if fd == state['fresh_fd']:
                raise cleanup
        with fixture.environment(), patch.object(source, 'process', process), patch.object(source, 'read_fd', read_fd), \
                patch.object(fixture, 'body', body), patch.object(source, 'close_fd', close):
            with self.assertRaises(RuntimeError) as escaped:
                d.discover(source, fixture.outer, d.Mode.PEER,
                    lambda lease: legacy.DiscoveryTests().consume_peer(lease), failure_site=observed.append)
            self.assertIs(escaped.exception, cleanup)
            self.assertEqual(len(work_errors), 1)
            self.assertEqual(observed, ['mreadclose'])
            self.assertEqual(source.owned, fixture.baseline)
            self.assertEqual(fixture.trace.count(('close', state['fresh_fd'])), 1)
            source.release_since(frozenset())
            self.assertEqual(source.owned, set())

    def test_process_and_recheck_operation_escapes_retain_actual_exception_and_custody(self):
        process_sites = ('mprocpid', 'mprocstartvalue', 'mprocpidfd', 'mprocdir', 'mprocfs',
            'mprocstart', 'mproccgroup', 'mprocwithin', 'mprocroot', 'mprocns', 'mprocstatus',
            'mprocidentity', 'mproccheck', 'mtimeopen', 'mtimelive', 'mtimeregister')
        check_sites = ('mcheckbudget', 'mchecklive', 'mcheckstart', 'mcheckcgroup', 'mcheckstatus',
            'mcheckreopen', 'mcheckidentity', 'mcheckclose', 'mctimeopen', 'mctimematch', 'mctimeclose')
        predicate_sites = {'mprocpid', 'mprocstartvalue', 'mprocfs', 'mprocstart', 'mprocwithin',
            'mchecklive', 'mcheckstart', 'mcheckcgroup', 'mcheckstatus', 'mcheckidentity', 'mctimematch'}
        for site in (*process_sites, *check_sites):
            fixture = SyntheticSource()
            source = fixture.source
            observer = b.matching_observation()
            work = RuntimeError('PRIVATE_PROCESS_OPERATION')
            with self.subTest(site=site), fixture.environment(), ExitStack() as stack:
                proc = source.process(110, 1100) if site in check_sites else None
                original_open, original_read, original_close = source.open, source.read, source.close_fd
                original_identity, original_magic = b.identity, b.fs_magic
                def opened(name, parent=None, directory=False, magic=False, observer=None):
                    targets = {'mprocdir': '110', 'mprocroot': 'root', 'mprocns': 'ns/pid',
                        'mcheckreopen': '110', 'mtimeopen': 'ns/time', 'mctimeopen': 'ns/time'}
                    if site in targets and name == targets[site]:
                        raise work
                    return b.matching_call(observer, original_open, name, parent, directory=directory, magic=magic)
                stack.enter_context(patch.object(source, 'open', opened))
                def read(parent, name, cap, observer=None):
                    if (site == 'mproccgroup' and name == 'cgroup') or (site == 'mprocstatus' and name == 'status'):
                        raise work
                    body = b.matching_call(observer, original_read, parent, name, cap)
                    if site == 'mcheckstatus' and name == 'status':
                        return body.replace(b'Uid: 1000 1000 1000 1000', b'Uid: 1000 0 0 0')
                    return body
                stack.enter_context(patch.object(source, 'read', read))
                if site == 'mprocpidfd':
                    stack.enter_context(patch.object(b.os, 'pidfd_open', side_effect=work))
                elif site == 'mprocfs':
                    stack.enter_context(patch.object(b, 'fs_magic', side_effect=lambda fd, observer=None:
                        0 if fixture.objects[fd][0] == 'procdir' else original_magic(fd, observer=observer)))
                elif site == 'mprocidentity':
                    def identity(fd):
                        if fixture.objects[fd][0] == 'root':
                            raise work
                        return original_identity(fd)
                    stack.enter_context(patch.object(b, 'identity', identity))
                elif site == 'mproccheck':
                    stack.enter_context(patch.object(source, 'check_process', side_effect=work))
                elif site == 'mtimelive':
                    stack.enter_context(patch.object(l, 'live', side_effect=work))
                elif site == 'mtimeregister':
                    class BrokenRegister(dict):
                        def __setitem__(self, key, value):
                            raise work
                    source.process_times = BrokenRegister()
                elif site == 'mcheckbudget':
                    stack.enter_context(patch.object(source.budget, 'check', side_effect=work))
                elif site == 'mchecklive':
                    stack.enter_context(patch.object(b.select, 'select', return_value=([proc.pidfd], [], [])))
                elif site == 'mcheckstart':
                    fixture.processes[110][0] += 1
                elif site == 'mcheckcgroup':
                    fixture.processes[110][1] = ('owned', 'threads', 'b')
                elif site == 'mcheckidentity':
                    stack.enter_context(patch.object(b, 'identity', side_effect=lambda fd:
                        (999, 999) if fixture.objects[fd][0] == 'root' else original_identity(fd)))
                elif site in ('mcheckclose', 'mctimeclose'):
                    def close(fd):
                        kind, value = fixture.objects[fd]
                        original_close(fd)
                        if ((site == 'mcheckclose' and kind == 'procdir') or
                                (site == 'mctimeclose' and kind == 'namespace' and value[0] == 'time')):
                            raise work
                    stack.enter_context(patch.object(source, 'close_fd', close))
                elif site == 'mctimematch':
                    source.reader_time_namespace = fixture.initial('namespace', ('time', 99))
                if site in check_sites:
                    call = lambda: source.check_process(proc, observer=observer)
                else:
                    call = lambda: source.process(0 if site == 'mprocpid' else 110,
                        0 if site == 'mprocstartvalue' else 1101 if site == 'mprocstart' else 1100,
                        SimpleNamespace(membership=fixture.processes[110][1]) if site == 'mprocwithin' else None,
                        observer=observer)
                error = self.assert_site(observer, site, call, b.Refusal if site in predicate_sites else RuntimeError)
                if site not in predicate_sites:
                    self.assertIs(error, work)
            with fixture.environment():
                source.release_since(fixture.baseline)
                self.assertEqual(source.owned, fixture.baseline)

    def test_namespace_ancestry_operations_keep_original_parent_reservations_and_refusals(self):
        sites = ('mnamespaceactive', 'mnamespacedepth', 'mnamespacereserve', 'mnamespaceparent',
            'mnamespaceadopt', 'mnamespacecycle', 'mnamespaceobjects')
        for site in sites:
            fixture = SyntheticSource()
            observer = b.matching_observation()
            work = RuntimeError('PRIVATE_NAMESPACE_OPERATION')
            with self.subTest(site=site), fixture.environment(), ExitStack() as stack:
                active = fixture.initial('namespace', ('pid', 110))
                original_identity = b.identity
                if site == 'mnamespaceactive':
                    stack.enter_context(patch.object(b, 'identity', side_effect=work))
                elif site == 'mnamespacedepth':
                    fixture.parents = {number: number - 1 for number in range(1, 111)}
                elif site == 'mnamespacereserve':
                    stack.enter_context(patch.object(fixture.source.budget, 'fd', side_effect=work))
                elif site == 'mnamespaceparent':
                    stack.enter_context(patch.object(l.fcntl, 'ioctl', side_effect=OSError('PRIVATE_PARENT')))
                elif site == 'mnamespaceadopt':
                    stack.enter_context(patch.object(b.os, 'set_inheritable', side_effect=work))
                elif site == 'mnamespacecycle':
                    fixture.parents[110] = 110
                elif site == 'mnamespaceobjects':
                    # The first identity of active is the loop test. The next
                    # occurs only while constructing the original result vector.
                    calls = []
                    fixture.objects[active] = 'namespace', ('pid', 0)
                    def identity(fd):
                        if fd == active:
                            calls.append(fd)
                            if len(calls) == 2:
                                raise work
                        return original_identity(fd)
                    stack.enter_context(patch.object(b, 'identity', identity))
                kind = b.Refusal if site in ('mnamespacedepth', 'mnamespacecycle') else l.LocatorRefusal if site == 'mnamespaceparent' else RuntimeError
                error = self.assert_site(observer, site, lambda: fixture.source.namespace_chain(active, (110, 2), observer=observer), kind)
                if kind is RuntimeError:
                    self.assertIs(error, work)
                if site == 'mnamespaceparent':
                    self.assertEqual(error.category, 'NamespaceUnreachable')
            with fixture.environment():
                fixture.source.release_since(fixture.baseline)

    def test_lease_entry_binding_scope_callback_select_finish_and_rollback_predicates(self):
        sites = ('mleaseentry', 'mrecord', 'mprocbind', 'mstatussame', 'mscope', 'mcallback',
            'mcallbackpure', 'mselect', 'mfinishstate', 'mfinishroles', 'mfinishseen', 'mrollback')
        for site in sites:
            fixture = SyntheticSource()
            observer = b.matching_observation()
            work = RuntimeError('PRIVATE_CALLBACK')
            source = fixture.source
            with self.subTest(site=site), fixture.environment(), ExitStack() as stack:
                borrowed = fixture.initial('procdir', 110) if site == 'mscope' else None
                baseline = frozenset(source.owned)
                record = d.Provisional(110, 1100, (30, 110), ('owned', 'threads', 'a'), 0, 0)
                cleanup = d._Cleanup(source, baseline)
                lease = d._Lease(source, d.Mode.WORKERS if site == 'mfinishseen' else d.Mode.PEER, (record,), cleanup, observer=observer)
                if site == 'mleaseentry':
                    lease._retired = True
                original_process = source.process
                def process(pid, start, observer=None):
                    proc = b.matching_call(observer, original_process, pid, start)
                    if site == 'mprocbind':
                        return replace(proc, start=proc.start + 1)
                    if site == 'mscope':
                        return replace(proc, directory=borrowed)
                    if site == 'mstatussame':
                        original_body = fixture.body
                        def body(fd):
                            return original_body(fd).replace(b'Uid: 1000 1000 1000 1000', b'Uid: 1000 0 0 0')
                        stack.enter_context(patch.object(fixture, 'body', body))
                    return proc
                stack.enter_context(patch.object(source, 'process', process))
                def run():
                    if site == 'mfinishseen':
                        # Roles are independently complete, but not one original
                        # provisional candidate has been inspected.
                        lease._selected = {role: None for role in d.Role if role is not d.Role.PEER}
                        return lease.finish()
                    if site in ('mfinishstate', 'mfinishroles'):
                        if site == 'mfinishstate':
                            lease._active = object()
                        return lease.finish()
                    with lease.acquire(replace(record) if site == 'mrecord' else record) as candidate:
                        if site in ('mcallback', 'mrollback'):
                            if site == 'mrollback':
                                fixture.fail_close = lambda fd: fixture.objects[fd][0] == 'pidfd'
                            raise work
                        if site == 'mcallbackpure':
                            source.budget.reads += 1
                        if site == 'mselect':
                            lease.select('peer', candidate)
                error = self.assert_site(observer, site, run, RuntimeError if site == 'mcallback' else b.Refusal)
                if site == 'mcallback':
                    self.assertIs(error, work)
                fixture.fail_close = None
                source.release_since(baseline)
                self.assertEqual(source.owned, baseline)

    def test_outer_cleanup_supersedes_matching_site_and_first_error_policy_is_unchanged(self):
        fixture = SyntheticSource()
        observed = []
        work, first, second = RuntimeError('PRIVATE_WORK'), ValueError('PRIVATE_FIRST'), OSError('PRIVATE_SECOND')
        failures = []
        original_release = fixture.source.release_since
        def release(previous):
            original_release(previous)
            failures.append(None)
            raise first if len(failures) == 1 else second
        def consume(lease):
            # Failure inside an actual acquisition first enters mrollback;
            # the original outer cleanup owns final release provenance.
            with lease.acquire(lease.candidates[0]):
                raise work
        with fixture.environment(), patch.object(fixture.source, 'release_since', release):
            with self.assertRaises(ValueError) as caught:
                d.discover(fixture.source, fixture.outer, d.Mode.PEER, consume, failure_site=observed.append)
        self.assertIs(caught.exception, first)
        self.assertEqual(observed, ['discrelease'])
        self.assertEqual(len(failures), 4)
        self.assertEqual(fixture.source.owned, fixture.baseline)

    def test_only_the_actual_escaping_exception_owns_the_site_and_references_are_cleared(self):
        for same_object in (False, True):
            fixture = SyntheticSource()
            observer = b.matching_observation()
            observed, errors = [], []
            replacement = RuntimeError('PRIVATE_REPLACEMENT')
            def consume(lease):
                try:
                    with lease.acquire(lease.candidates[0]) as candidate:
                        lease.select('peer', candidate)  # the original exact Role guard fails
                except b.Refusal as error:
                    errors.append(error)
                    if same_object:
                        raise
                raise replacement
            with self.subTest(same_object=same_object), fixture.environment(), patch.object(b, 'matching_observation', return_value=observer):
                try:
                    d.discover(fixture.source, fixture.outer, d.Mode.PEER, consume, failure_site=observed.append)
                except BaseException as caught:
                    self.assertIs(caught, errors[0] if same_object else replacement)
                else:
                    self.fail('original callback failure must escape')
            self.assertEqual(observed, ['mselect' if same_object else 'discmatch'])
            self.assertIsNone(observer.exception)
            self.assertIsNone(observer.token)
            self.assertTrue(observer.frozen)
            self.assertEqual(fixture.source.owned, fixture.baseline)
        class Hostile(Exception):
            def __getattribute__(self, _name):
                raise AssertionError('custom exception property inspected')
            def __eq__(self, _other):
                raise AssertionError('exception equality inspected')
            def __str__(self):
                raise AssertionError('exception text inspected')
            def __repr__(self):
                raise AssertionError('exception representation inspected')
        first, second = Hostile(), Hostile()
        observer = b.matching_observation()
        b._matching_update(observer, 'mprivate', first)
        ordinary = b.matching_scope(observer, 'mcallback')
        self.assertEqual(ordinary.previous, (None, None))
        with ordinary:
            self.assertIsNone(observer.exception)
        self.assertIsNone(ordinary.previous)
        b._matching_update(observer, 'mprivate', first)
        cleanup = b.matching_scope(observer, 'mrollback', cleanup=True)
        self.assertIs(cleanup.previous[1], first)
        with cleanup:
            self.assertIsNone(observer.exception)
        self.assertIs(observer.exception, first)
        self.assertIsNone(cleanup.previous)
        self.assertEqual(b.matching_finish(observer, first), 'mprivate')
        self.assertIsNone(observer.exception)
        for replacement in (first, second):
            observer = b.matching_observation()
            try:
                with b.matching_scope(observer, 'mcallback'):
                    try:
                        with b.matching_scope(observer, 'mprivate'):
                            raise first
                    except Hostile:
                        pass
                    raise replacement
            except Hostile as escaped:
                self.assertIs(escaped, replacement)
                self.assertEqual(b.matching_finish(observer, escaped), 'mprivate' if replacement is first else 'mcallback')
            self.assertIsNone(observer.exception)
            self.assertIsNone(observer.token)
        observer = b.matching_observation()
        fixture = SyntheticSource()
        with fixture.environment(), patch.object(b, 'matching_observation', return_value=observer):
            transfer = d.discover(fixture.source, fixture.outer, d.Mode.PEER,
                lambda lease: legacy.DiscoveryTests().consume_peer(lease), failure_site=lambda _: self.fail('success emitted'))
            transfer.close()
        self.assertIsNone(observer.exception)
        self.assertIsNone(observer.token)
        self.assertTrue(observer.frozen)
        for damage in (MemoryError, KeyboardInterrupt):
            fixture = SyntheticSource()
            original = RuntimeError('PRIVATE_ORIGINAL')
            def consume(lease):
                with lease.acquire(lease.candidates[0]):
                    raise original
            with fixture.environment(), patch.object(b, '_MatchingScope', side_effect=damage):
                try:
                    d.discover(fixture.source, fixture.outer, d.Mode.PEER, consume,
                        failure_site=lambda _: (_ for _ in ()).throw(damage()))
                except RuntimeError as escaped:
                    self.assertIs(escaped, original)
                else:
                    self.fail('metadata damage replaced the original failure')
            self.assertEqual(fixture.source.owned, fixture.baseline)

    def test_scope_cleanup_precedence_handled_failures_and_metadata_damage(self):
        for cleanup_fails in (False, True):
            observer = b.matching_observation()
            work, cleanup = RuntimeError('PRIVATE_WORK'), ValueError('PRIVATE_CLOSE')
            def run():
                with b.matching_scope(observer, 'mcallback'):
                    try:
                        with b.matching_scope(observer, 'mprivate'):
                            raise work
                    finally:
                        with b.matching_scope(observer, 'mrollback', cleanup=True):
                            if cleanup_fails:
                                raise cleanup
            with self.assertRaises(ValueError if cleanup_fails else RuntimeError) as caught:
                run()
            self.assertIs(caught.exception, cleanup if cleanup_fails else work)
            self.assertEqual(b.matching_site(observer), 'mrollback' if cleanup_fails else 'mprivate')
        observer = b.matching_observation()
        with b.matching_scope(observer, 'mcallback'):
            try:
                with b.matching_scope(observer, 'mprivate'):
                    raise ValueError('handled')
            except ValueError:
                pass
            with self.assertRaises(b.Refusal):
                with b.matching_scope(observer, 'mselect'):
                    b.require(False)
            self.assertEqual(b.matching_site(observer), 'mselect')
        self.assertIsNone(b.matching_site(observer))
        for damage in (MemoryError, KeyboardInterrupt):
            observer = b.matching_observation()
            with patch.object(b._MatchingObservation, 'note', side_effect=damage):
                self.assertIs(b._observe(False, observer, 'cap'), False)
            self.assertIsNone(b.matching_site(observer))
            self.assertFalse(observer.valid)
        for damage in (MemoryError, KeyboardInterrupt):
            fixture = SyntheticSource()
            with fixture.environment(), patch.object(b, '_MatchingObservation', side_effect=damage):
                transfer = d.discover(fixture.source, fixture.outer, d.Mode.PEER,
                    lambda lease: legacy.DiscoveryTests().consume_peer(lease), failure_site=lambda _: self.fail('success emitted'))
                transfer.close()
