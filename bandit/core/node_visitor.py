#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0
import ast
import logging
import operator

from bandit.core import constants
from bandit.core import tester as b_tester
from bandit.core import utils as b_utils

LOG = logging.getLogger(__name__)


_NESTED_SCOPE_NODES = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.Lambda,
    ast.ClassDef,
    ast.ListComp,
    ast.SetComp,
    ast.DictComp,
    ast.GeneratorExp,
)

_COMPREHENSION_NODES = (
    ast.ListComp,
    ast.SetComp,
    ast.DictComp,
    ast.GeneratorExp,
)

_TRY_NODES = (ast.Try,) + ((ast.TryStar,) if hasattr(ast, "TryStar") else ())

_MATCH_AS = getattr(ast, "MatchAs", None)
_MATCH_STAR = getattr(ast, "MatchStar", None)
_MATCH_MAPPING = getattr(ast, "MatchMapping", None)

_ABSENT = object()
_SHADOWED = object()


def _target_names(target):
    """Names bound by an assignment-like target."""
    names = set()
    if isinstance(target, ast.Name):
        names.add(target.id)
    elif isinstance(target, ast.Starred):
        names.update(_target_names(target.value))
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            names.update(_target_names(elt))
    return names


def _param_names(args):
    """Names bound by a function/lambda signature."""
    names = set()
    for arg in args.posonlyargs + args.args + args.kwonlyargs:
        names.add(arg.arg)
    if args.vararg:
        names.add(args.vararg.arg)
    if args.kwarg:
        names.add(args.kwarg.arg)
    return names


def _collect_scope_names(node):
    """Collect names bound in a function-like scope.

    Emulates Python's static scoping: any name bound anywhere in the
    body is local to the whole scope unless declared global/nonlocal.
    Nested scopes are not descended into.
    """
    globals_ = set()
    nonlocals_ = set()
    locals_ = set()

    def visit(obj):
        for child in ast.iter_child_nodes(obj):
            if isinstance(child, _NESTED_SCOPE_NODES):
                name = getattr(child, "name", None)
                if isinstance(name, str):
                    locals_.add(name)
            elif isinstance(child, ast.Global):
                globals_.update(child.names)
            elif isinstance(child, ast.Nonlocal):
                nonlocals_.update(child.names)
            elif isinstance(child, ast.Import):
                for alias in child.names:
                    locals_.add(alias.asname or alias.name.split(".")[0])
            elif isinstance(child, ast.ImportFrom):
                for alias in child.names:
                    if alias.name != "*":
                        locals_.add(alias.asname or alias.name)
            elif isinstance(child, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = getattr(child, "targets", None) or [child.target]
                for target in targets:
                    locals_.update(_target_names(target))
                visit(child)
            elif isinstance(child, (ast.For, ast.AsyncFor)):
                locals_.update(_target_names(child.target))
                visit(child)
            elif isinstance(child, (ast.With, ast.AsyncWith)):
                for item in child.items:
                    if item.optional_vars is not None:
                        locals_.update(_target_names(item.optional_vars))
                visit(child)
            elif isinstance(child, ast.ExceptHandler):
                if child.name:
                    locals_.add(child.name)
                visit(child)
            elif isinstance(child, ast.NamedExpr):
                locals_.update(_target_names(child.target))
                visit(child)
            elif isinstance(child, ast.Delete):
                for target in child.targets:
                    locals_.update(_target_names(target))
            elif _MATCH_AS is not None and isinstance(
                child, (_MATCH_AS, _MATCH_STAR)
            ):
                if child.name:
                    locals_.add(child.name)
            elif _MATCH_MAPPING is not None and isinstance(
                child, _MATCH_MAPPING
            ):
                if child.rest:
                    locals_.add(child.rest)
                visit(child)
            else:
                visit(child)

    visit(node)
    return globals_, nonlocals_, locals_


class _Scope:
    """A single lexical scope for import alias resolution."""

    __slots__ = (
        "kind",
        "parent",
        "aliases",
        "shadowed",
        "globals",
        "nonlocals",
    )

    def __init__(self, kind, parent=None):
        self.kind = kind  # module, function, lambda, class, comprehension
        self.parent = parent
        self.aliases = {}  # name -> qualified name
        self.shadowed = set()  # names rebound to something unknown
        self.globals = set()
        self.nonlocals = set()


class _ScopeTracker:
    """Tracks lexical scopes and the import aliases visible in them."""

    def __init__(self):
        self.module_scope = _Scope("module")
        self.current = self.module_scope

    def push(self, kind, node=None):
        scope = _Scope(kind, self.current)
        if kind in ("function", "lambda"):
            globals_, nonlocals_, locals_ = _collect_scope_names(node)
            scope.globals.update(globals_)
            scope.nonlocals.update(nonlocals_)
            scope.shadowed.update(locals_ - globals_ - nonlocals_)
            scope.shadowed.update(_param_names(node.args))
        elif kind == "comprehension":
            for generator in node.generators:
                scope.shadowed.update(_target_names(generator.target))
        self.current = scope

    def pop(self):
        self.current = self.current.parent

    def _target_scope(self, name):
        scope = self.current
        if name in scope.globals:
            return self.module_scope
        if name in scope.nonlocals:
            target = scope.parent
            while target is not None and target.kind == "class":
                target = target.parent
            while target is not None and target.kind not in (
                "function",
                "lambda",
            ):
                target = target.parent
            return target if target is not None else self.module_scope
        return scope

    def bind_alias(self, name, qualname):
        scope = self._target_scope(name)
        scope.aliases[name] = qualname
        scope.shadowed.discard(name)

    def bind_shadow(self, name):
        scope = self._target_scope(name)
        scope.shadowed.add(name)
        scope.aliases.pop(name, None)

    def poison_star_import(self):
        # A star import may rebind any name in the current namespace,
        # so previously known aliases can no longer be trusted.
        scope = self.current
        scope.shadowed.update(scope.aliases)
        scope.aliases.clear()

    def declare_global(self, names):
        self.current.globals.update(names)

    def declare_nonlocal(self, names):
        self.current.nonlocals.update(names)

    def snapshot(self):
        return (dict(self.current.aliases), set(self.current.shadowed))

    def restore(self, state):
        self.current.aliases = dict(state[0])
        self.current.shadowed = set(state[1])

    def merge_branch_states(self, states):
        """Merge scope states produced by alternative branches.

        A name bound consistently in every branch keeps that binding;
        anything else is treated as unknown.
        """
        scope = self.current
        names = set()
        for aliases, shadowed in states:
            names.update(aliases)
            names.update(shadowed)
        for name in names:
            values = set()
            for aliases, shadowed in states:
                if name in shadowed:
                    values.add(_SHADOWED)
                elif name in aliases:
                    values.add(aliases[name])
                else:
                    values.add(_ABSENT)
            if len(values) == 1:
                value = values.pop()
                if value is _ABSENT:
                    scope.aliases.pop(name, None)
                    scope.shadowed.discard(name)
                elif value is _SHADOWED:
                    scope.aliases.pop(name, None)
                    scope.shadowed.add(name)
                else:
                    scope.aliases[name] = value
                    scope.shadowed.discard(name)
            else:
                scope.aliases.pop(name, None)
                scope.shadowed.add(name)

    def effective_aliases(self):
        """Import aliases visible from the current scope.

        Class scopes are only visible to code directly in the class
        body; names bound in a class body are not closures for methods.
        """
        chain = []
        scope = self.current
        first = True
        while scope is not None:
            if scope.kind == "class" and not first:
                scope = scope.parent
                continue
            chain.append(scope)
            first = False
            scope = scope.parent
        merged = {}
        for scope in reversed(chain):
            for name in scope.shadowed:
                merged.pop(name, None)
            merged.update(scope.aliases)
        return merged


class BanditNodeVisitor:
    def __init__(
        self, fname, fdata, metaast, testset, debug, nosec_lines, metrics
    ):
        self.debug = debug
        self.nosec_lines = nosec_lines
        self.scores = {
            "SEVERITY": [0] * len(constants.RANKING),
            "CONFIDENCE": [0] * len(constants.RANKING),
        }
        self.depth = 0
        self.fname = fname
        self.fdata = fdata
        self.metaast = metaast
        self.testset = testset
        self.imports = set()
        self._scopes = _ScopeTracker()
        self.tester = b_tester.BanditTester(
            self.testset, self.debug, nosec_lines, metrics
        )

        # in some cases we can't determine a qualified name
        try:
            self.namespace = b_utils.get_module_qualname_from_path(fname)
        except b_utils.InvalidModulePath:
            LOG.warning(
                "Unable to find qualified name for module: %s", self.fname
            )
            self.namespace = ""
        LOG.debug("Module qualified name: %s", self.namespace)
        self.metrics = metrics

    @property
    def import_aliases(self):
        """Import aliases visible in the current scope."""
        return self._scopes.effective_aliases()

    def visit_ClassDef(self, node):
        """Visitor for AST ClassDef node

        Add class name to current namespace for all descendants.
        :param node: Node being inspected
        :return: -
        """
        # For all child nodes, add this class name to current namespace
        self.namespace = b_utils.namespace_path_join(self.namespace, node.name)

    def visit_FunctionDef(self, node):
        """Visitor for AST FunctionDef nodes

        add relevant information about the node to
        the context for use in tests which inspect function definitions.
        Add the function name to the current namespace for all descendants.
        :param node: The node that is being inspected
        :return: -
        """

        self.context["function"] = node
        qualname = self.namespace + "." + b_utils.get_func_name(node)
        name = qualname.split(".")[-1]

        self.context["qualname"] = qualname
        self.context["name"] = name

        # For all child nodes and any tests run, add this function name to
        # current namespace
        self.namespace = b_utils.namespace_path_join(self.namespace, name)
        self.update_scores(self.tester.run_tests(self.context, "FunctionDef"))

    def visit_Call(self, node):
        """Visitor for AST Call nodes

        add relevant information about the node to
        the context for use in tests which inspect function calls.
        :param node: The node that is being inspected
        :return: -
        """

        self.context["call"] = node
        qualname = b_utils.get_call_name(node, self.import_aliases)
        name = qualname.split(".")[-1]

        self.context["qualname"] = qualname
        self.context["name"] = name

        self.update_scores(self.tester.run_tests(self.context, "Call"))

    def visit_Import(self, node):
        """Visitor for AST Import nodes

        add relevant information about node to
        the context for use in tests which inspect imports.
        :param node: The node that is being inspected
        :return: -
        """
        for nodename in node.names:
            if nodename.asname:
                self._scopes.bind_alias(nodename.asname, nodename.name)
            else:
                # Plain 'import a.b' binds the top level name 'a'; an
                # identity alias keeps natural name resolution working
                # when the import is local to a nested scope.
                top_name = nodename.name.split(".")[0]
                self._scopes.bind_alias(top_name, top_name)
            self.imports.add(nodename.name)
            self.context["module"] = nodename.name
        self.update_scores(self.tester.run_tests(self.context, "Import"))

    def visit_ImportFrom(self, node):
        """Visitor for AST ImportFrom nodes

        add relevant information about node to
        the context for use in tests which inspect imports.
        :param node: The node that is being inspected
        :return: -
        """
        module = node.module
        if module is None:
            return self.visit_Import(node)

        for nodename in node.names:
            if nodename.name == "*":
                # A star import brings in names we cannot enumerate, so
                # we can no longer claim to know where any previously
                # imported name in this scope comes from.
                self._scopes.poison_star_import()
            elif nodename.asname:
                self._scopes.bind_alias(
                    nodename.asname, module + "." + nodename.name
                )
            else:
                # Even if import is not aliased we need an entry that maps
                # name to module.name.  For example, with 'from a import b'
                # b should be aliased to the qualified name a.b
                self._scopes.bind_alias(
                    nodename.name, module + "." + nodename.name
                )
            self.imports.add(module + "." + nodename.name)
            self.context["module"] = module
            self.context["name"] = nodename.name
        self.update_scores(self.tester.run_tests(self.context, "ImportFrom"))

    def visit_Constant(self, node):
        """Visitor for AST Constant nodes

        call the appropriate method for the node type.
        this maintains compatibility with <3.6 and 3.8+

        This code is heavily influenced by Anthony Sottile (@asottile) here:
        https://bugs.python.org/msg342486

        :param node: The node that is being inspected
        :return: -
        """
        if isinstance(node.value, str):
            self.visit_Str(node)
        elif isinstance(node.value, bytes):
            self.visit_Bytes(node)

    def visit_Str(self, node):
        """Visitor for AST String nodes

        add relevant information about node to
        the context for use in tests which inspect strings.
        :param node: The node that is being inspected
        :return: -
        """
        self.context["str"] = node.value
        if not isinstance(node._bandit_parent, ast.Expr):  # docstring
            self.context["linerange"] = b_utils.linerange(node._bandit_parent)
            self.update_scores(self.tester.run_tests(self.context, "Str"))

    def visit_Bytes(self, node):
        """Visitor for AST Bytes nodes

        add relevant information about node to
        the context for use in tests which inspect strings.
        :param node: The node that is being inspected
        :return: -
        """
        self.context["bytes"] = node.value
        if not isinstance(node._bandit_parent, ast.Expr):  # docstring
            self.context["linerange"] = b_utils.linerange(node._bandit_parent)
            self.update_scores(self.tester.run_tests(self.context, "Bytes"))

    def pre_visit(self, node):
        self.context = {}
        self.context["imports"] = self.imports
        self.context["import_aliases"] = self.import_aliases

        if self.debug:
            LOG.debug(ast.dump(node))
            self.metaast.add_node(node, "", self.depth)

        if hasattr(node, "lineno"):
            self.context["lineno"] = node.lineno

        if hasattr(node, "col_offset"):
            self.context["col_offset"] = node.col_offset
        if hasattr(node, "end_col_offset"):
            self.context["end_col_offset"] = node.end_col_offset

        self.context["node"] = node
        self.context["linerange"] = b_utils.linerange(node)
        self.context["filename"] = self.fname
        self.context["file_data"] = self.fdata

        LOG.debug(
            "entering: %s %s [%s]", hex(id(node)), type(node), self.depth
        )
        self.depth += 1
        LOG.debug(self.context)
        return True

    def visit(self, node):
        name = node.__class__.__name__
        method = "visit_" + name
        visitor = getattr(self, method, None)
        if visitor is not None:
            if self.debug:
                LOG.debug("%s called (%s)", method, ast.dump(node))
            visitor(node)
        else:
            self.update_scores(self.tester.run_tests(self.context, name))
        self._track_scope_bindings(node)

    def _track_scope_bindings(self, node):
        """Update scope bindings for statements that (re)bind names."""
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # The def itself binds its name in the enclosing scope; the
            # function scope is only entered in generic_visit.
            self._scopes.bind_shadow(node.name)
        elif isinstance(node, ast.ClassDef):
            self._scopes.bind_shadow(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                self._bind_target(target)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            self._bind_target(node.target)
        elif isinstance(node, ast.NamedExpr):
            self._bind_target(node.target)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            self._bind_target(node.target)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    self._bind_target(item.optional_vars)
        elif isinstance(node, ast.ExceptHandler):
            # 'except X as name' binds name for the handler body and
            # deletes it afterwards; either way the previous meaning of
            # the name can no longer be assumed.
            if node.name:
                self._scopes.bind_shadow(node.name)
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                self._bind_target(target)
        elif isinstance(node, ast.Global):
            self._scopes.declare_global(node.names)
        elif isinstance(node, ast.Nonlocal):
            self._scopes.declare_nonlocal(node.names)

    def _bind_target(self, target):
        for name in _target_names(target):
            self._scopes.bind_shadow(name)

    def post_visit(self, node):
        self.depth -= 1
        LOG.debug("%s\texiting : %s", self.depth, hex(id(node)))

        # HACK(tkelsey): this is needed to clean up post-recursion stuff that
        # gets setup in the visit methods for these node types.
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            self.namespace = b_utils.namespace_path_split(self.namespace)[0]

    def generic_visit(self, node):
        """Drive the visitor."""
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Decorators, defaults and annotations are evaluated in the
            # enclosing scope; the body gets its own scope.
            self._visit_children(node.decorator_list, node)
            self._visit_child(node.args, node)
            if node.returns is not None:
                self._visit_child(node.returns, node)
            self._scopes.push("function", node)
            self._visit_children(node.body, node)
            self._scopes.pop()
            return
        if isinstance(node, ast.Lambda):
            self._visit_child(node.args, node)
            self._scopes.push("lambda", node)
            self._visit_child(node.body, node)
            self._scopes.pop()
            return
        if isinstance(node, ast.ClassDef):
            self._visit_children(node.decorator_list, node)
            self._visit_children(node.bases, node)
            self._visit_children(node.keywords, node)
            self._scopes.push("class", node)
            self._visit_children(node.body, node)
            self._scopes.pop()
            return
        if isinstance(node, _COMPREHENSION_NODES):
            self._scopes.push("comprehension", node)
            self._visit_children(node.generators, node)
            if isinstance(node, ast.DictComp):
                self._visit_child(node.key, node)
                self._visit_child(node.value, node)
            else:
                self._visit_child(node.elt, node)
            self._scopes.pop()
            return
        if isinstance(node, ast.If):
            # Names rebound in only some branches cannot be resolved
            # with certainty afterwards.
            self._visit_child(node.test, node)
            base = self._scopes.snapshot()
            states = []
            self._visit_children(node.body, node)
            states.append(self._scopes.snapshot())
            self._scopes.restore(base)
            self._visit_children(node.orelse, node)
            states.append(self._scopes.snapshot())
            self._scopes.restore(base)
            self._scopes.merge_branch_states(states)
            return
        if isinstance(node, _TRY_NODES):
            base = self._scopes.snapshot()
            states = []
            self._visit_children(node.body, node)
            # The else clause runs when the body succeeds, so it
            # continues from the body state.
            self._visit_children(node.orelse, node)
            states.append(self._scopes.snapshot())
            self._scopes.restore(base)
            for handler in node.handlers:
                self._visit_child(handler, node)
                states.append(self._scopes.snapshot())
                self._scopes.restore(base)
            self._scopes.merge_branch_states(states)
            # The finally clause always runs.
            self._visit_children(node.finalbody, node)
            return
        for _, value in ast.iter_fields(node):
            if isinstance(value, list):
                self._visit_children(
                    [item for item in value if isinstance(item, ast.AST)],
                    node,
                )
            elif isinstance(value, ast.AST):
                self._visit_child(value, node)

    def _visit_child(self, node, parent):
        node._bandit_sibling = None
        node._bandit_parent = parent
        if self.pre_visit(node):
            self.visit(node)
            self.generic_visit(node)
            self.post_visit(node)

    def _visit_children(self, nodes, parent):
        max_idx = len(nodes) - 1
        for idx, item in enumerate(nodes):
            if idx < max_idx:
                item._bandit_sibling = nodes[idx + 1]
            else:
                item._bandit_sibling = None
            item._bandit_parent = parent
            if self.pre_visit(item):
                self.visit(item)
                self.generic_visit(item)
                self.post_visit(item)

    def update_scores(self, scores):
        """Score updater

        Since we moved from a single score value to a map of scores per
        severity, this is needed to update the stored list.
        :param score: The score list to update our scores with
        """
        # we'll end up with something like:
        # SEVERITY: {0, 0, 0, 10}  where 10 is weighted by finding and level
        for score_type in self.scores:
            self.scores[score_type] = list(
                map(operator.add, self.scores[score_type], scores[score_type])
            )

    def process(self, data):
        """Main process loop

        Build and process the AST
        :param lines: lines code to process
        :return score: the aggregated score for the current file
        """
        f_ast = ast.parse(data)
        self.generic_visit(f_ast)
        # Run tests that do not require access to the AST,
        # but only to the whole file source:
        self.context = {
            "file_data": self.fdata,
            "filename": self.fname,
            "lineno": 0,
            "linerange": [0, 1],
            "col_offset": 0,
        }
        self.update_scores(self.tester.run_tests(self.context, "File"))
        return self.scores
