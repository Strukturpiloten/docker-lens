"""Strict matching-only AST erasure; immutable snapshots retain original work."""
import ast
import copy

# These lists authorize fixed metadata syntax, never native calls or predicates.
SITES = {
    'read_fd': ('mreadseek', 'mreadsyscall', 'mreadcap'),
    'read': ('mreadopen', 'mreadfs', 'mreadclose', 'mbudgetreads', 'mbudgetbytes'),
    'check': ('mbudgettime',), 'fd': ('mbudgetfds', 'mbudgetopens'),
    'process': ('mprocpid', 'mprocstartvalue', 'mprocpidfd', 'mprocdir', 'mprocfs', 'mprocstart',
        'mproccgroup', 'mprocwithin', 'mprocroot', 'mprocns', 'mprocstatus', 'mprocidentity',
        'mproccheck', 'mtimeopen', 'mtimematch', 'mtimelive', 'mtimeregister'),
    'check_process': ('mcheckbudget', 'mchecklive', 'mcheckstart', 'mcheckcgroup', 'mcheckstatus',
        'mcheckreopen', 'mcheckidentity', 'mcheckclose', 'mctimeopen', 'mctimematch', 'mctimeclose'),
    'namespace_chain': ('mnamespaceactive', 'mnamespacedepth', 'mnamespacereserve', 'mnamespaceparent',
        'mnamespaceadopt', 'mnamespacecycle', 'mnamespaceobjects', 'mnamespacevector'),
    'start_from_stat': ('mstatdelimiter', 'mstatstate', 'mstatstart'),
    'cgroup_path': ('mcgrouprecord',),
    'process_status': ('mstatusfields', 'mstatuspid', 'mstatustgid', 'mstatusuid', 'mstatusnspid'),
    'fd_mount_id': ('mfdmount',), 'status_vectors': ('mstatusnstgid',),
    'acquire': ('mleaseentry', 'mrecord', 'mprocbind', 'mstatussame', 'mscope', 'mcallback', 'mcallbackpure', 'mrollback'),
    'select': ('mselect',), 'finish': ('mfinishstate', 'mfinishroles', 'mfinishseen'),
    'consume': ('mprivate', 'mambiguous', 'mnomatch'),
}
CALLS = {
    'process': ('self.budget.fd', 'self.open', 'fs_magic', 'start_from_stat', 'self.read', 'cgroup_path',
        'process_status', 'self.fd_mount_id', 'self.check_process', 'super().process'),
    'check_process': ('self.budget.check', 'self.read', 'start_from_stat', 'cgroup_path', 'process_status',
        'self.open', 'self.fd_mount_id', 'super().check_process'),
    'read': ('self.open', 'fs_magic', 'self.read_fd'),
    'fd_mount_id': ('self.read',), 'status_vectors': ('boundary.process_status',),
    'namespace_chain': ('self.budget.fd',),
    'acquire': ('self.source.process', 'locator.status_vectors', 'self.source.read', 'self.source.namespace_chain'),
}

def normalized_matching_metadata(method):
    method = copy.deepcopy(method)
    observer = 'self._matching' if method.name in ('acquire', 'select', 'finish') else (
        'lease._matching' if method.name == 'consume' else 'observer')
    dump = lambda value: ast.dump(value, include_attributes=False)
    observer_ast = dump(ast.parse(observer, mode='eval').body)
    wrappers = ('matching_call', 'boundary.matching_call')
    scopes = ('matching_scope', 'boundary.matching_scope')
    class Erase(ast.NodeTransformer):
        def visit_FunctionDef(self, node):
            if node is not method:
                return normalized_matching_metadata(node)
            return self.generic_visit(node)
        def visit_If(self, node):
            if method.name == '_discover' and ast.unparse(node.test) == 'observer is None':
                expected = ast.parse('if observer is None:\n    lease = _Lease(source, mode, records, cleanup)\nelse:\n    lease = _Lease(source, mode, records, cleanup, observer=observer)').body[0]
                assert ast.dump(node) == ast.dump(expected), 'unreviewed default-None lease forwarding'
                return node.body
            return self.generic_visit(node)
        def visit_Call(self, node):
            if ast.unparse(node.func) in wrappers:
                assert len(node.args) >= 2 and dump(node.args[0]) == observer_ast, 'unreviewed matching observer'
                assert ast.unparse(node.args[1]) in CALLS.get(method.name, ()), 'unreviewed matching callee'
                assert not any(k.arg == 'observer' for k in node.keywords), 'unreviewed matching keyword'
                return self.visit(ast.Call(func=node.args[1], args=node.args[2:], keywords=node.keywords))
            return self.generic_visit(node)
        def visit_With(self, node):
            kept = []
            for item in node.items:
                call = item.context_expr
                if isinstance(call, ast.Call) and ast.unparse(call.func) in scopes:
                    assert len(call.args) == 2 and dump(call.args[0]) == observer_ast, 'unreviewed matching scope'
                    assert isinstance(call.args[1], ast.Constant) and call.args[1].value in SITES.get(method.name, ()), 'unreviewed matching site'
                    assert item.optional_vars is None
                    expected = [ast.keyword(arg='cleanup', value=ast.Constant(True))] if call.args[1].value in (
                        'mreadclose', 'mcheckclose', 'mctimeclose', 'mrollback') else []
                    assert [dump(k) for k in call.keywords] == [dump(k) for k in expected], 'unreviewed matching cleanup'
                else:
                    kept.append(item)
            node.items = kept
            self.generic_visit(node)
            return node if kept else node.body
        def visit_Assign(self, node):
            if method.name == '__init__' and dump(node) == dump(ast.parse('self._matching = observer').body[0]):
                return None
            return self.generic_visit(node)
    return Erase().visit(method)
