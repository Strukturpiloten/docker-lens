"""Strict metadata-only AST erasure shared by immutable source controls."""
import ast
import copy


def normalized_type_metadata(method):
    method = copy.deepcopy(method)
    if method.name == "check_group" and not any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "_type_observation" for n in ast.walk(method)):
        return method

    # Approve complete, original-arity/default-None branches before erasure.
    # A matching keyword alone cannot authorize changing a native call signature.
    def parsed_method(signature, body):
        return ast.parse("def " + signature + ":\n" + "\n".join("    " + line for line in body.splitlines())).body[0]

    def forwarding(default, observed, parameter="observer"):
        return "if " + parameter + " is None:\n    " + default + "\nelse:\n    " + observed

    check_forwarding = forwarding("self.check()", "self.check(observer=observer)")
    read_forwarding = forwarding("self.budget.read(capacity)", "self.budget.read(capacity, observer=observer)")
    templates = (
        parsed_method("read(self, maximum, observer=None)", check_forwarding),
        parsed_method("fd(self, observer=None)", check_forwarding),
        parsed_method("open(self, name, parent=None, directory=False, magic=False, observer=None)",
            forwarding("self.budget.fd()", "self.budget.fd(observer=observer)")),
        parsed_method("read_fd(self, fd, maximum, observer=None)", read_forwarding),
        parsed_method("check_group(self, group, observer=None)", forwarding(
            'fd = self.open("cgroup.type", group.directories[-1])',
            'fd = _observe(self.open("cgroup.type", group.directories[-1], observer=detail), detail, "opened")', "detail")),
        parsed_method("check_group(self, group, observer=None)", forwarding(
            'require(fs_magic(fd) == CGROUP_MAGIC and self.read_fd(fd, 32) == b"domain\\n")',
            'require(_observe(fs_magic(fd, observer=detail) == CGROUP_MAGIC, detail, "m_guard") and _observe(self.read_fd(fd, 32, observer=detail), detail, "domain") == b"domain\\n")', "detail")),
    )
    permitted_branches = {ast.dump(template.body[0]) for template in templates
        if template.name == method.name and ast.dump(template.args) == ast.dump(method.args)}
    branches, plumbing_calls = set(), set()
    for node in ast.walk(method):
        if isinstance(node, ast.If) and ast.dump(node) in permitted_branches:
            branches.add(id(node))
            for statement in node.orelse:
                plumbing_calls.update(id(call) for call in ast.walk(statement) if isinstance(call, ast.Call)
                    and any(keyword.arg == "observer" for keyword in call.keywords))

    type_scope = ast.parse('_group_escape(observer, "gv_type", detail=detail)', mode="eval").body
    if method.name == "check_group" and permitted_branches:
        scope = method.body[-1]
        if (isinstance(scope, ast.With) and len(scope.items) == 1 and scope.items[0].optional_vars is None
                and ast.dump(scope.items[0].context_expr) == ast.dump(type_scope)):
            plumbing_calls.add(id(scope.items[0].context_expr))
    for node in ast.walk(method):
        if isinstance(node, ast.Call) and any(keyword.arg in ("observer", "detail") for keyword in node.keywords):
            assert id(node) in plumbing_calls, "unreviewed observer/detail callee, argument shape, or forwarding context"

    class Erase(ast.NodeTransformer):
        def visit_FunctionDef(self, node):
            self.generic_visit(node)
            if node.args.args[-1].arg in ("observer", "detail"):
                # Existing observer parameters are retained except on newly plumbed primitives.
                if node.name not in ("check_group", "_group_escape", "escape") or node.args.args[-1].arg == "detail":
                    assert ast.dump(node.args.defaults[-1]) == "Constant(value=None)"
                    node.args.args.pop(); node.args.defaults.pop()
            return node

        def visit_Call(self, node):
            if ast.dump(node.func) in (ast.dump(ast.parse('_observe', mode='eval').body), ast.dump(ast.parse('boundary._observe', mode='eval').body)):
                assert len(node.args) == 3 and not node.keywords
                assert isinstance(node.args[1], ast.Name) and node.args[1].id in ("observer", "detail")
                assert isinstance(node.args[2], ast.Constant) and node.args[2].value in (
                    "time", "fds", "opens", "reads", "bytes", "cap", "m_syscall", "m_guard", "domain", "opened")
                return self.visit(node.args[0])
            self.generic_visit(node)
            for keyword in list(node.keywords):
                if keyword.arg in ("observer", "detail"):
                    assert id(node) in plumbing_calls
                    node.keywords.remove(keyword)
            return node

        def visit_Expr(self, node):
            call = node.value
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "_observe" and isinstance(call.args[0], ast.Constant) and call.args[0].value is None:
                assert ast.dump(call.args[1]) == "Name(id='detail', ctx=Load())"
                assert call.args[2].value in ("cleanup_enter", "cleanup_done")
                assert len(call.args) == 3 and not call.keywords
                return None
            return self.generic_visit(node)

        def visit_Assign(self, node):
            if method.name == "check_group" and ast.dump(node.targets[0]) == "Name(id='detail', ctx=Store())":
                assert ast.dump(node.value) == ast.dump(ast.parse('_type_observation(observer)', mode='eval').body)
                return None
            if method.name == "_group_escape":
                if ast.dump(node.targets[0]) == "Name(id='token', ctx=Store())":
                    # Explicit closed metadata gate; no source call may be erased here.
                    assert ast.dump(node.value) == ast.dump(ast.parse('detail.token if (site == "gv_type" and tag == "unclassified" and type(detail) is _TypeObservation and detail.valid and type(detail.token) is str and detail.token in _TYPE_DETAILS) else None', mode='eval').body)
                    return None
                if isinstance(node.targets[0], ast.Tuple):
                    assert ast.dump(node) == ast.dump(ast.parse('tag, token = "unclassified", None').body[0])
                    return ast.parse('tag = "unclassified"').body[0]
            if method.name == "escape":
                if ast.dump(node.targets[0]) == "Name(id='suffix', ctx=Store())":
                    assert ast.dump(node.value) == ast.dump(ast.parse('"" if detail is None else " d=" + detail', mode='eval').body)
                    return None
                if ast.dump(node.targets[0]) == "Attribute(value=Name(id='self', ctx=Load()), attr='value', ctx=Store())" and isinstance(node.value, ast.IfExp):
                    assert ast.dump(node.value) == ast.dump(ast.parse('(site, exception) if detail is None else (site, exception, detail)', mode='eval').body)
                    node.value = node.value.body
            return self.generic_visit(node)

        def visit_JoinedStr(self, node):
            if method.name == "escape":
                node.values = [value for value in node.values if not (isinstance(value, ast.FormattedValue) and isinstance(value.value, ast.Name) and value.value.id == "suffix")]
            return self.generic_visit(node)

        def visit_BoolOp(self, node):
            self.generic_visit(node)
            if method.name == "escape" and isinstance(node.op, ast.And):
                forbidden = [ast.parse('detail is None', mode='eval').body,
                    ast.parse('detail is None or (site == "gv_type" and exception == "unclassified" and type(detail) is str and detail in HOST_TYPE_DETAILS)', mode='eval').body]
                node.values = [value for value in node.values if all(ast.dump(value) != ast.dump(item) for item in forbidden)]
            return node

        def visit_If(self, node):
            if method.name == "_group_escape" and ast.dump(node.test) == ast.dump(ast.parse('token is None', mode='eval').body):
                assert ast.dump(node.body[0]) == ast.dump(ast.parse('observer(site, tag)').body[0])
                assert ast.dump(node.orelse[0]) == ast.dump(ast.parse('observer(site, tag, token)').body[0])
                assert len(node.body) == len(node.orelse) == 1
                return node.body[0]
            self.generic_visit(node)
            if ast.dump(node.test) in [ast.dump(ast.parse(text, mode='eval').body) for text in ('observer is None', 'detail is None')]:
                assert id(node) in branches, "unreviewed default-None forwarding branch"
                assert [ast.dump(n) for n in node.body] == [ast.dump(n) for n in node.orelse]
                return node.body
            return node
    return Erase().visit(method)
