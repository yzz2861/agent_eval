"""Bounded Python AST subset for rule comparison.

Only the node kinds in SUPPORTED_NODES are in scope. Everything else is
reported as uncovered rather than silently interpreted. The subset covers
the three required behaviours: call aliasing, constant conditions and simple
assignment. Enumeration is bounded structurally and by a program budget, so
the search always terminates.
"""

import ast
import itertools


SUPPORTED_NODES = frozenset({
    ast.Module, ast.Import, ast.ImportFrom, ast.alias, ast.Assign,
    ast.Expr, ast.If, ast.Name, ast.Constant, ast.Call, ast.Attribute,
    ast.Store, ast.Load,
})

UNSUPPORTED_NODE_NAMES = (
    "FunctionDef", "AsyncFunctionDef", "ClassDef", "Return", "For",
    "AsyncFor", "While", "Try", "With", "AsyncWith", "Lambda", "ListComp",
    "SetComp", "DictComp", "GeneratorExp", "Await", "Yield", "BinOp",
    "BoolOp", "Compare", "Subscript", "Dict", "List", "Set", "Tuple",
)

SUPPORTED_CONSTANT_TYPES = (bool, type(None), int, str)


class Bounds(object):
    """Inclusive structural limits for generated programs."""

    def __init__(self, max_statements=6, max_if_depth=2, max_name_length=3,
                 max_program_count=4000):
        self.max_statements = max_statements
        self.max_if_depth = max_if_depth
        self.max_name_length = max_name_length
        self.max_program_count = max_program_count

    def as_dict(self):
        return {
            "max_statements": self.max_statements,
            "max_if_depth": self.max_if_depth,
            "max_name_length": self.max_name_length,
            "max_program_count": self.max_program_count,
        }


class Coverage(object):
    """Declarative record of what the subset covers and what it does not."""

    def __init__(self, supported_node_types, unsupported_node_types,
                 constant_types, bounds, uncovered_note):
        self.supported_node_types = tuple(supported_node_types)
        self.unsupported_node_types = tuple(unsupported_node_types)
        self.constant_types = tuple(constant_types)
        self.bounds = bounds
        self.uncovered_note = uncovered_note

    def as_dict(self):
        return {
            "supported_node_types": list(self.supported_node_types),
            "unsupported_node_types": list(self.unsupported_node_types),
            "constant_types": [t.__name__ for t in self.constant_types],
            "bounds": self.bounds.as_dict(),
            "uncovered_note": self.uncovered_note,
        }


def unparse(tree):
    """Render an AST back to canonical, compilable source."""
    return ast.unparse(tree)


def is_in_subset(tree):
    """True when every node in ``tree`` is a supported node kind."""
    return all(type(node) in SUPPORTED_NODES for node in ast.walk(tree))


def unsupported_kinds(tree):
    """Sorted node class names in ``tree`` that fall outside the subset."""
    return sorted({
        type(node).__name__ for node in ast.walk(tree)
        if type(node) not in SUPPORTED_NODES
    })


def _name(value):
    return ast.Name(id=value, ctx=ast.Load())


def _const(value):
    return ast.Constant(value=value)


def _call(callee):
    # Calls in the subset take no arguments.
    return ast.Call(func=callee, args=[], keywords=[])


def _attribute(module_name, attr):
    return ast.Attribute(value=_name(module_name), attr=attr, ctx=ast.Load())


def _import(module_name, alias=None):
    return ast.Import(names=[ast.alias(name=module_name, asname=alias)])


def _from_import(module_name, attr, alias=None):
    return ast.ImportFrom(module=module_name, level=0,
                          names=[ast.alias(name=attr, asname=alias)])


def _assign(target_name, value):
    return ast.Assign(targets=[ast.Name(id=target_name, ctx=ast.Store())],
                       value=value)


def _if(condition, body, orelse=None):
    return ast.If(test=condition, body=body, orelse=orelse or [])


def _expr_stmt(value):
    return ast.Expr(value=value)


class BoundedSubset(object):
    """The fixed, explicitly bounded Python AST subset."""

    name = "bounded-python-ast-subset-v1"
    uncovered_note = (
        "Constructs beyond simple imports, zero-argument calls, constant "
        "conditions and literal assignments (functions, classes, loops, "
        "try/with, comprehensions, operators, subscripts, collections, "
        "argument-carrying calls, etc.) are OUT OF SCOPE and are only "
        "declared uncovered; they are never treated as evidence."
    )

    def __init__(self, bounds=None):
        self.bounds = bounds or Bounds()

    def coverage(self):
        return Coverage(
            supported_node_types=sorted(n.__name__ for n in SUPPORTED_NODES),
            unsupported_node_types=UNSUPPORTED_NODE_NAMES,
            constant_types=SUPPORTED_CONSTANT_TYPES,
            bounds=self.bounds,
            uncovered_note=self.uncovered_note,
        )

    def declare_coverage(self, requested_features):
        """Split requested feature names into covered and uncovered."""
        supported = set(self.coverage().supported_node_types)
        covered = [f for f in requested_features if f in supported]
        uncovered = [f for f in requested_features if f not in supported]
        return covered, uncovered

    def iter_programs(self):
        generator = ProgramGenerator(self.bounds)
        return generator.programs()


# Public default instance used by the comparison backend.
SUBSET = BoundedSubset()


class ProgramGenerator(object):
    """Enumerate unique, compilable source strings inside the bounds."""

    def __init__(self, bounds=None, modules=None, callees=None,
                 variables=None, constants=None):
        self.bounds = bounds or Bounds()
        self.modules = modules or ("os", "subprocess")
        self.callees = callees or ("system", "eval", "run", "danger")
        self.variables = (
            variables or ("a", "b", "c")[: self.bounds.max_name_length]
        )
        self.constants = (
            constants if constants is not None
            else (True, False, None, 0, 1, "x")
        )

    def _import_statements(self):
        statements = []
        for module_name in self.modules:
            statements.append(_import(module_name))
            statements.append(_import(module_name, module_name[0]))
            for callee in self.callees[:2]:
                statements.append(_from_import(module_name, callee))
                statements.append(_from_import(module_name, callee, callee[0]))
        return statements

    def _call_expressions(self):
        expressions = []
        for callee in self.callees:
            expressions.append(_call(_name(callee)))
            for module_name in self.modules:
                expressions.append(_call(_attribute(module_name, callee)))
        for module_name in self.modules:
            expressions.append(_call(_name(module_name[0])))
        for callee in self.callees[:2]:
            expressions.append(_call(_name(callee[0])))
        return expressions

    def _assignment_statements(self):
        return [
            _assign(variable, _const(value))
            for variable in self.variables
            for value in self.constants
        ]

    def _leaf_statements(self):
        leaves = list(self._import_statements())
        leaves.extend(self._assignment_statements())
        leaves.extend(_expr_stmt(expr) for expr in self._call_expressions())
        return leaves

    def _condition_wraps(self, body):
        variants = [body]
        for condition in self.constants:
            wrapped = _if(_const(condition), body)
            variants.append([wrapped])
        return variants

    def programs(self):
        """Yield unique, compile-checked source strings up to the budget."""
        seen = set()
        emitted = 0
        leaves = self._leaf_statements()

        def emit(statements):
            nonlocal emitted
            if emitted >= self.bounds.max_program_count:
                return
            if len(statements) > self.bounds.max_statements:
                return
            module = ast.Module(body=list(statements), type_ignores=[])
            ast.fix_missing_locations(module)
            if not is_in_subset(module):
                return
            source = ast.unparse(module)
            if source in seen:
                return
            seen.add(source)
            ast.parse(source)  # guarantee compilability before yielding
            emitted += 1
            yield source

        # Single statements, including constant-condition wrappers.
        for leaf in leaves:
            for variant in self._condition_wraps([leaf]):
                for source in emit(variant):
                    yield source

        # Pairs let a rule correlate an import/assignment with a later call.
        for first, second in itertools.combinations(leaves, 2):
            for variant in self._condition_wraps([first, second]):
                for source in emit(variant):
                    yield source

        # A nested-if program exercises the if-depth bound.
        nested = _if(_const(True), [_if(_const(False), [leaves[0]])])
        for source in emit([nested]):
            yield source


def extract_premises(source):
    """Human-readable structural premises that a witness relies on."""
    tree = ast.parse(source)
    premises = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name
                premises.append(
                    "import alias: name %r is bound to %r" % (bound, alias.name)
                )
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                bound = alias.asname or alias.name
                premises.append(
                    "from-import alias: %r is bound to %s.%r"
                    % (bound, node.module, alias.name)
                )
        elif isinstance(node, ast.If):
            value = node.test.value if isinstance(node.test, ast.Constant) else "?"
            premises.append("constant condition: if %r" % (value,))
        elif isinstance(node, ast.Assign):
            target = node.targets[0].id
            value = node.value.value if isinstance(node.value, ast.Constant) else "?"
            premises.append("simple assignment: %s = %r" % (target, value))
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                callee = "%s.%s" % (node.func.value.id, node.func.attr)
            elif isinstance(node.func, ast.Name):
                callee = node.func.id
            else:
                callee = "?"
            premises.append("zero-argument call: %s()" % callee)
    # De-duplicate while preserving order.
    return list(dict.fromkeys(premises))
