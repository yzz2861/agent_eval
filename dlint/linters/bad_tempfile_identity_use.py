#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast
import collections
import itertools

from . import base
from .. import tree


_ASYNC_FUNCTION_DEF = getattr(ast, "AsyncFunctionDef", ())
_ASYNC_WITH = getattr(ast, "AsyncWith", ())
_ASYNC_FOR = getattr(ast, "AsyncFor", ())


AnalysisBoundary = collections.namedtuple(
    'AnalysisBoundary',
    ['lineno', 'col_offset', 'reason']
)


_TEMP_FILE_CREATORS = {
    'NamedTemporaryFile': {
        'delete': True,
        'persistent': False,
        'returns': 'object',
    },
    'TemporaryFile': {
        'delete': True,
        'persistent': False,
        'returns': 'object',
    },
    'SpooledTemporaryFile': {
        'delete': True,
        'persistent': False,
        'returns': 'object',
    },
    'TemporaryDirectory': {
        'delete': True,
        'persistent': False,
        'returns': 'object',
    },
    'mkstemp': {
        'delete': False,
        'persistent': True,
        'returns': 'tuple',
    },
    'mkdtemp': {
        'delete': False,
        'persistent': True,
        'returns': 'path',
    },
}

# Methods which release the object's ownership of the path. For a
# NamedTemporaryFile with the default `delete=True` this unlinks the path.
_CLOSE_METHODS = frozenset([
    'close',
    'detach',
    '__exit__',
    'rollover',
])

_FORCED_CLOSE_METHODS = frozenset([
    'cleanup',
])

_BENIGN_OBJECT_METHODS = frozenset([
    'read',
    'read1',
    'readinto',
    'readline',
    'readlines',
    'write',
    'writelines',
    'seek',
    'tell',
    'truncate',
    'flush',
    'fileno',
    'isatty',
    'readable',
    'writable',
    'seekable',
    'mode',
    'encoding',
    'errors',
    'newlines',
    'closed',
    'softspace',
    '__enter__',
    'name',
])

_BENIGN_BUILTIN_CALLS = frozenset([
    'open',
    'print',
    'str',
    'repr',
    'format',
    'len',
    'bool',
    'bytes',
    'int',
    'float',
    'id',
    'hash',
    'type',
    'isinstance',
    'getattr',
    'hasattr',
    'setattr',
])

_BENIGN_MODULE_FUNCTIONS = frozenset([
    'bz2.open',
    'codecs.open',
    'csv.reader',
    'csv.writer',
    'io.open',
    'gzip.open',
    'json.dump',
    'json.dumps',
    'json.load',
    'json.loads',
    'os.access',
    'os.fdopen',
    'os.fspath',
    'os.listdir',
    'os.lstat',
    'os.open',
    'os.readlink',
    'os.scandir',
    'os.stat',
    'os.path.abspath',
    'os.path.basename',
    'os.path.dirname',
    'os.path.exists',
    'os.path.getatime',
    'os.path.getctime',
    'os.path.getmtime',
    'os.path.getsize',
    'os.path.isdir',
    'os.path.isfile',
    'os.path.islink',
    'os.path.join',
    'os.path.lexists',
    'os.path.normpath',
    'os.path.realpath',
    'os.path.relpath',
    'os.path.samefile',
    'os.path.split',
    'os.path.splitext',
    'pathlib.Path',
    'pickle.dump',
    'pickle.load',
    'shutil.copy',
    'shutil.copy2',
    'shutil.copyfile',
    'shutil.copyfileobj',
    'shutil.copytree',
    'shutil.disk_usage',
    'subprocess.call',
    'subprocess.check_call',
    'subprocess.check_output',
    'subprocess.Popen',
    'subprocess.run',
    'tarfile.open',
    'yaml.dump',
    'yaml.load',
    'yaml.safe_dump',
    'yaml.safe_load',
    'zipfile.ZipFile',
])

_CONSUMING_PATH_FUNCTIONS = frozenset([
    'os.remove',
    'os.removedirs',
    'os.rename',
    'os.replace',
    'os.rmdir',
    'os.unlink',
    'shutil.move',
    'shutil.rmtree',
])

_CONSUMING_PATH_METHODS = frozenset([
    'rename',
    'replace',
    'rmdir',
    'unlink',
])


class _Token(object):
    """The identity a temporary-path value is pinned to."""

    __slots__ = (
        'uid',
        'kind',
        'delete',
        'persistent',
        'creation',
        'path_proven',
        'loss_node',
        'loss_reason',
        'reported',
    )

    def __init__(self, uid, kind, delete, persistent, creation):
        self.uid = uid
        self.kind = kind
        self.delete = delete
        self.persistent = persistent
        self.creation = creation
        self.path_proven = True
        self.loss_node = None
        self.loss_reason = None
        self.reported = False

    def clone(self):
        token = _Token(
            self.uid,
            self.kind,
            self.delete,
            self.persistent,
            self.creation,
        )
        token.path_proven = self.path_proven
        token.loss_node = self.loss_node
        token.loss_reason = self.loss_reason
        token.reported = self.reported
        return token


class _StateMixin(object):
    """Small helpers shared by the analyzer and state merging."""

    @staticmethod
    def object_reference_count(state, uid):
        return sum(
            1 for bound_uid in state.objects.values()
            if bound_uid == uid
        )

    def drop_orphaned_paths(self, node):
        referenced = set(self.paths.values())
        for uid in referenced:
            token = self.tokens.get(uid)
            if token is None or not token.path_proven:
                continue
            if token.persistent:
                continue
            if self.object_reference_count(self, uid) == 0:
                token.path_proven = False
                token.loss_node = node
                token.loss_reason = 'temporary object was released'


class _State(_StateMixin):
    """Per-path state: bindings and the identity tokens they reference."""

    def __init__(self, tokens=None, objects=None, paths=None):
        self.tokens = tokens if tokens is not None else {}
        self.objects = objects if objects is not None else {}
        self.paths = paths if paths is not None else {}

    def clone(self):
        return _State(
            tokens={
                uid: token.clone()
                for uid, token in self.tokens.items()
            },
            objects=dict(self.objects),
            paths=dict(self.paths),
        )


def _source_before(left, right):
    return (left.lineno, left.col_offset) < (right.lineno, right.col_offset)


def _merge_tokens(left, right):
    left.path_proven = left.path_proven and right.path_proven
    left.reported = left.reported or right.reported

    if right.loss_node is not None:
        if left.loss_node is None or _source_before(right.loss_node, left.loss_node):
            left.loss_node = right.loss_node
            left.loss_reason = right.loss_reason


def _merge_states(left, right, merge_node=None):
    result = left.clone()

    for uid, right_token in right.tokens.items():
        if uid in result.tokens:
            _merge_tokens(result.tokens[uid], right_token)
        else:
            result.tokens[uid] = right_token.clone()

    # A binding only survives a merge when both incoming paths agree on it.
    # If one path rebinds the name then we can no longer name the token.
    for name in list(result.objects):
        if right.objects.get(name) != result.objects[name]:
            del result.objects[name]
    for name in list(result.paths):
        if right.paths.get(name) != result.paths[name]:
            del result.paths[name]

    if merge_node is not None:
        result.drop_orphaned_paths(merge_node)

    return result


class _ScopeAnalyzer(_StateMixin):
    def __init__(self, linter, summaries, uid_counter):
        self.linter = linter
        self.summaries = summaries
        self.uid_counter = uid_counter
        self.namespace = linter.namespace
        self.local_aliases = {}

    def analyze(self, body):
        self.local_aliases = self.collect_local_aliases(body)
        state = _State()
        self.exec_body(body, state)

    def collect_local_aliases(self, body):
        aliases = {}

        def collect(statements):
            for statement in statements:
                if isinstance(statement, ast.Import):
                    for alias in statement.names:
                        bound = alias.asname or alias.name.split('.')[0]
                        aliases[bound] = alias.name
                elif isinstance(statement, ast.ImportFrom):
                    if not statement.module:
                        continue
                    for alias in statement.names:
                        if alias.name == '*':
                            continue
                        bound = alias.asname or alias.name
                        aliases[bound] = statement.module + '.' + alias.name
                elif isinstance(statement, (
                        ast.FunctionDef,
                        _ASYNC_FUNCTION_DEF,
                        ast.ClassDef,
                        ast.Lambda)):
                    continue
                else:
                    for child in ast.iter_child_nodes(statement):
                        if isinstance(child, ast.stmt):
                            collect([child])
                    handlers = getattr(statement, 'handlers', [])
                    for handler in handlers:
                        collect(handler.body)

        collect(body)
        return aliases

    def canonical_local_path(self, path):
        if path in self.local_aliases:
            return self.local_aliases[path]
        parts = path.split('.')
        if parts and parts[0] in self.local_aliases:
            return '.'.join([self.local_aliases[parts[0]]] + parts[1:])
        return path

    def new_token(self, state, kind, delete, persistent, creation):
        uid = next(self.uid_counter)
        state.tokens[uid] = _Token(
            uid,
            kind,
            delete,
            persistent,
            creation,
        )
        return uid

    def bind_object(self, state, name, uid, node=None):
        if state.objects.get(name) == uid:
            state.paths.pop(name, None)
            return
        self.unbind(state, name, node)
        state.paths.pop(name, None)
        state.objects[name] = uid

    def bind_path(self, state, name, uid, node=None):
        if state.paths.get(name) == uid:
            state.objects.pop(name, None)
            return
        self.unbind(state, name, node)
        state.objects.pop(name, None)
        state.paths[name] = uid

    def unbind(self, state, name, node, drop_orphan=True):
        if name in state.paths:
            del state.paths[name]
        if name not in state.objects:
            return

        uid = state.objects.pop(name)
        token = state.tokens.get(uid)
        if token is None or not drop_orphan or node is None:
            return
        if token.path_proven and not token.persistent:
            if self.object_reference_count(state, uid) == 0:
                self.mark_lost(
                    state,
                    uid,
                    node,
                    'last temporary object reference was reassigned',
                )

    def mark_lost(self, state, uid, node, reason):
        token = state.tokens.get(uid)
        if token is None:
            return
        token.path_proven = False
        if token.loss_node is None:
            token.loss_node = node
            token.loss_reason = reason

    def mark_close(self, state, uid, node, reason, force=False):
        token = state.tokens.get(uid)
        if token is None:
            return
        if token.persistent and not force:
            return
        self.mark_lost(state, uid, node, reason)

    def record_path_use(self, state, uid, node):
        token = state.tokens.get(uid)
        if token is None or token.path_proven or token.reported:
            return

        loss_node = token.loss_node if token.loss_node is not None else node
        self.linter.results.append(
            base.Flake8Result(
                lineno=loss_node.lineno,
                col_offset=loss_node.col_offset,
                message=self.linter._error_tmpl,
            )
        )
        token.reported = True

    def record_boundary(self, node, reason):
        self.linter.boundaries.append(
            AnalysisBoundary(
                lineno=node.lineno,
                col_offset=node.col_offset,
                reason=reason,
            )
        )

    def mark_boundary(self, state, uid, node, reason):
        token = state.tokens.get(uid)
        if token is None:
            return
        if not token.path_proven:
            return
        self.mark_lost(state, uid, node, reason)
        self.record_boundary(node, reason)

    @staticmethod
    def target_names(target):
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, ast.Attribute):
            return [tree.module_path_str(target)]
        if isinstance(target, (ast.Tuple, ast.List)):
            names = []
            for child in target.elts:
                names.extend(_ScopeAnalyzer.target_names(child))
            return names
        return []

    def bind_targets(self, state, targets, binder, uid, node):
        for target in targets:
            for name in self.target_names(target):
                binder(state, name, uid, node)

    def unbind_targets(self, state, targets, node):
        for target in targets:
            for name in self.target_names(target):
                self.unbind(state, name, node)

    def object_uid(self, node, state):
        if isinstance(node, (ast.Name, ast.Attribute)):
            return state.objects.get(tree.module_path_str(node))
        return None

    def path_uid(self, node, state):
        if isinstance(node, (ast.Name, ast.Attribute)):
            direct = state.paths.get(tree.module_path_str(node))
            if direct is not None:
                return direct

        if isinstance(node, ast.Attribute) and node.attr == 'name':
            return self.object_uid(node.value, state)

        return None

    @staticmethod
    def literal_bool(node):
        if isinstance(node, ast.Name) and node.id in ('True', 'False'):
            return node.id == 'True'
        name_constant = getattr(ast, 'NameConstant', None)
        if name_constant is not None and isinstance(node, name_constant):
            return node.value
        constant = getattr(ast, 'Constant', None)
        if constant is not None and isinstance(node, constant):
            if isinstance(node.value, bool):
                return node.value
        return None

    def kwarg(self, call, name):
        for keyword in call.keywords:
            if keyword.arg == name:
                return keyword.value
        return None

    def matches_module_function(self, func, canonical):
        path = self.canonical_local_path(tree.module_path_str(func))
        if path == canonical:
            return True
        return self.namespace.illegal_module_imported(path, canonical)

    @staticmethod
    def contains_name(node, name):
        return any(
            isinstance(child, ast.Name) and child.id == name
            for child in ast.walk(node)
        )

    def tempfile_creator_name(self, func):
        path = self.canonical_local_path(tree.module_path_str(func))

        for name in _TEMP_FILE_CREATORS:
            if self.namespace.illegal_module_imported(
                    path, 'tempfile.' + name):
                return name

        # Locally scoped imports are intentionally outside of
        # `namespace.Namespace`, so accept the unambiguous spellings too.
        for name in _TEMP_FILE_CREATORS:
            if path == 'tempfile.' + name:
                return name

        if isinstance(func, ast.Name) and func.id in _TEMP_FILE_CREATORS:
            return func.id

        return None

    def creation_info(self, call):
        if not isinstance(call, ast.Call):
            return None

        name = self.tempfile_creator_name(call.func)
        if name is None:
            return None

        info = dict(_TEMP_FILE_CREATORS[name])
        info['name'] = name

        if info['returns'] == 'object' and name in (
                'NamedTemporaryFile', 'TemporaryDirectory'):
            delete_expr = self.kwarg(call, 'delete')
            if delete_expr is not None:
                if isinstance(delete_expr, ast.Name):
                    info['delete_param'] = delete_expr.id
                delete = self.literal_bool(delete_expr)
                info['delete'] = delete
                info['persistent'] = delete is False

        return info

    def classify_call(self, call):
        func = call.func

        if isinstance(func, ast.Name) and func.id in self.summaries:
            return ('helper', self.summaries[func.id])

        creation = self.creation_info(call)
        if creation is not None:
            return ('creation', creation)

        if isinstance(func, ast.Name) and func.id in _BENIGN_BUILTIN_CALLS:
            return ('benign', None)

        for canonical in _CONSUMING_PATH_FUNCTIONS:
            if self.matches_module_function(func, canonical):
                return ('consumes_path', None)

        for canonical in _BENIGN_MODULE_FUNCTIONS:
            if self.matches_module_function(func, canonical):
                return ('benign', None)

        if self.matches_module_function(func, 'os.close'):
            return ('benign', None)

        if self.matches_module_function(func, 'contextlib.closing'):
            return ('benign', None)
        if self.matches_module_function(func, 'contextlib.nullcontext'):
            return ('benign', None)

        return ('unknown', None)

    def call_arguments(self, call):
        arguments = []
        for argument in call.args:
            if isinstance(argument, ast.Starred):
                arguments.append(argument.value)
            else:
                arguments.append(argument)
        for keyword in call.keywords:
            arguments.append(keyword.value)
        return arguments

    def eval_call(self, node, state):
        if isinstance(node.func, ast.Attribute):
            object_uid = self.object_uid(node.func.value, state)
            if object_uid is not None:
                for argument in node.args:
                    self.eval_expr(argument, state)
                for keyword in node.keywords:
                    self.eval_expr(keyword.value, state)

                attribute = node.func.attr
                if attribute in _FORCED_CLOSE_METHODS:
                    self.mark_close(
                        state,
                        object_uid,
                        node,
                        'temporary object was closed by "' + attribute + '"',
                        force=True,
                    )
                elif attribute in _CLOSE_METHODS:
                    self.mark_close(
                        state,
                        object_uid,
                        node,
                        'temporary object was closed by "' + attribute + '"',
                    )
                elif attribute == 'name':
                    self.record_path_use(state, object_uid, node)
                elif attribute not in _BENIGN_OBJECT_METHODS:
                    # The receiver is still owned here. Unknown file methods do
                    # not transfer the path, so they are not a boundary.
                    pass
                return

            path_uid = self.path_uid(node.func.value, state)
            if path_uid is not None:
                self.eval_expr(node.func.value, state)
                if node.func.attr in _CONSUMING_PATH_METHODS:
                    self.mark_lost(
                        state,
                        path_uid,
                        node,
                        'temporary path was consumed by "' + node.func.attr + '"',
                    )
                for argument in node.args:
                    self.eval_expr(argument, state)
                for keyword in node.keywords:
                    self.eval_expr(keyword.value, state)
                return

            self.eval_expr(node.func.value, state)

            if node.func.attr in _CONSUMING_PATH_METHODS:
                for candidate in ast.walk(node.func.value):
                    if not isinstance(candidate, (ast.Name, ast.Attribute)):
                        continue
                    path_uid = self.path_uid(candidate, state)
                    if path_uid is not None:
                        self.mark_lost(
                            state,
                            path_uid,
                            node,
                            'temporary path was consumed by "' + node.func.attr + '"',
                        )

        effect, extra = self.classify_call(node)

        # Arguments are evaluated before applying the call's effect so that a
        # violating use is reported at the loss site, not at the call site.
        for argument in node.args:
            self.eval_expr(argument, state)
        for keyword in node.keywords:
            self.eval_expr(keyword.value, state)

        if effect == 'creation':
            return
        if effect == 'benign':
            return
        if effect == 'consumes_path':
            for argument in self.call_arguments(node):
                uid = self.path_uid(argument, state)
                if uid is not None:
                    self.mark_lost(
                        state,
                        uid,
                        node,
                        'temporary path was consumed by a helper',
                    )
            return
        if effect == 'helper':
            self.apply_helper_effect(extra, node, state)
            return

        # Unknown call: a path string has no ownership, so passing it is only
        # an analysis boundary. Passing the temporary object itself may hand
        # ownership (and therefore the path) to the callee.
        for argument in self.call_arguments(node):
            path_uid = self.path_uid(argument, state)
            if path_uid is not None:
                token = state.tokens.get(path_uid)
                if token is not None and token.path_proven:
                    self.record_boundary(
                        node,
                        'temporary path passed to an unknown call',
                    )
                continue

            object_uid = self.object_uid(argument, state)
            if object_uid is not None:
                self.mark_boundary(
                    state,
                    object_uid,
                    node,
                    'temporary object passed to an unknown call',
                )

    def helper_argument(self, summary, call):
        index = summary.get('index', 0)
        name = summary.get('param')

        if index < len(call.args):
            argument = call.args[index]
            if isinstance(argument, ast.Starred):
                return argument.value
            return argument

        if name is not None:
            for keyword in call.keywords:
                if keyword.arg == name:
                    return keyword.value

        return None

    def factory_creation(self, summary, call):
        creation = dict(summary['creation'])
        parameter = creation.get('delete_param')
        if parameter is None:
            return creation

        parameters = summary.get('parameters', [])
        argument = None
        if parameter in parameters:
            index = parameters.index(parameter)
            if index < len(call.args):
                argument = call.args[index]
        if argument is None:
            for keyword in call.keywords:
                if keyword.arg == parameter:
                    argument = keyword.value
                    break
        if argument is not None:
            delete = self.literal_bool(argument)
            creation['delete'] = delete
            creation['persistent'] = delete is False
        return creation

    def apply_helper_effect(self, summary, call, state):
        kind = summary['kind']
        if kind in ('benign', 'factory'):
            return

        argument = self.helper_argument(summary, call)
        if argument is None:
            return

        if kind == 'close':
            object_uid = self.object_uid(argument, state)
            if object_uid is not None:
                self.mark_close(
                    state,
                    object_uid,
                    call,
                    'temporary object was closed by a same-module helper',
                )
            else:
                path_uid = self.path_uid(argument, state)
                if path_uid is not None:
                    self.mark_lost(
                        state,
                        path_uid,
                        call,
                        'temporary path was closed by a same-module helper',
                    )
            return

        if kind == 'consumes_path':
            path_uid = self.path_uid(argument, state)
            if path_uid is not None:
                self.mark_lost(
                    state,
                    path_uid,
                    call,
                    'temporary path was consumed by a same-module helper',
                )

    def eval_expr(self, node, state):
        if node is None:
            return

        if isinstance(node, ast.Call):
            self.eval_call(node, state)
            return

        if isinstance(node, ast.Attribute):
            path_uid = self.path_uid(node, state)
            if path_uid is not None:
                self.record_path_use(state, path_uid, node)
            else:
                object_uid = self.object_uid(node.value, state)
                if object_uid is None:
                    self.eval_expr(node.value, state)
            return

        if isinstance(node, ast.Name):
            path_uid = state.paths.get(node.id)
            if path_uid is not None:
                self.record_path_use(state, path_uid, node)
            return

        if isinstance(node, ast.Lambda):
            return

        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                self.eval_expr(child, state)

    def exec_body(self, body, state):
        for statement in body:
            if self.exec_statement(statement, state):
                return True
        return False

    def exec_statement(self, node, state):
        if isinstance(node, ast.Assign):
            self.exec_assign(node, state)
            return False

        ann_assign = getattr(ast, 'AnnAssign', None)
        if ann_assign is not None and isinstance(node, ann_assign):
            if node.value is not None:
                self.exec_assign(node, state)
            return False

        if isinstance(node, ast.AugAssign):
            self.eval_expr(node.value, state)
            self.unbind_targets(state, [node.target], node)
            return False

        if isinstance(node, ast.Expr):
            self.eval_expr(node.value, state)
            return False

        if isinstance(node, ast.With):
            self.exec_with(node, state)
            return False

        async_with = getattr(ast, 'AsyncWith', None)
        if async_with is not None and isinstance(node, async_with):
            self.exec_with(node, state)
            return False

        if isinstance(node, ast.Try):
            return self.exec_try(node, state)

        try_star = getattr(ast, 'TryStar', None)
        if try_star is not None and isinstance(node, try_star):
            return self.exec_try(node, state)

        if isinstance(node, ast.If):
            return self.exec_if(node, state)

        if isinstance(node, (ast.For, ast.While)):
            self.exec_loop(node, state)
            return False

        async_for = getattr(ast, 'AsyncFor', None)
        if async_for is not None and isinstance(node, async_for):
            self.exec_loop(node, state)
            return False

        if isinstance(node, ast.Return):
            self.eval_expr(node.value, state)
            return True

        if isinstance(node, ast.Raise):
            self.eval_expr(node.exc, state)
            return True

        if isinstance(node, (ast.Break, ast.Continue)):
            return True

        if isinstance(node, ast.Delete):
            for target in node.targets:
                for name in self.target_names(target):
                    self.unbind(state, name, node)
            return False

        if isinstance(node, ast.Assert):
            self.eval_expr(node.test, state)
            self.eval_expr(node.msg, state)
            return False

        function_defs = (ast.FunctionDef, ast.ClassDef)
        async_function_def = getattr(ast, 'AsyncFunctionDef', None)
        if async_function_def is not None:
            function_defs = function_defs + (async_function_def,)
        if isinstance(node, function_defs):
            # Each nested scope is analyzed independently.
            return False

        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                self.eval_expr(child, state)
        return False

    def exec_assign(self, node, state):
        value = node.value
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]

        if isinstance(value, (ast.Tuple, ast.List)) and len(targets) == 1:
            target = targets[0]
            if isinstance(target, (ast.Tuple, ast.List)):
                self.exec_unpack(target, value, state, node)
                return

        if isinstance(value, ast.Call):
            creation = self.creation_info(value)
            effect, extra = self.classify_call(value)

            for argument in value.args:
                self.eval_expr(argument, state)
            for keyword in value.keywords:
                self.eval_expr(keyword.value, state)

            if effect == 'helper':
                self.apply_helper_effect(extra, value, state)

            if creation is not None:
                if creation['returns'] == 'path':
                    uid = self.new_token(
                        state,
                        creation['name'],
                        creation['delete'],
                        creation['persistent'],
                        node,
                    )
                    self.bind_targets(state, targets, self.bind_path, uid, node)
                elif creation['returns'] == 'tuple':
                    self.exec_mkstemp_assign(targets, value, creation, state, node)
                else:
                    uid = self.new_token(
                        state,
                        creation['name'],
                        creation['delete'],
                        creation['persistent'],
                        node,
                    )
                    self.bind_targets(state, targets, self.bind_object, uid, node)
                return

            if effect == 'helper':
                summary = extra
                kind = summary['kind']
                if kind == 'factory':
                    creation = self.factory_creation(summary, value)
                    if creation['returns'] == 'path':
                        uid = self.new_token(
                            state,
                            creation['name'],
                            creation['delete'],
                            creation['persistent'],
                            node,
                        )
                        self.bind_targets(state, targets, self.bind_path, uid, node)
                    else:
                        uid = self.new_token(
                            state,
                            creation['name'],
                            creation['delete'],
                            creation['persistent'],
                            node,
                        )
                        self.bind_targets(state, targets, self.bind_object, uid, node)
                    return

                if kind in ('return_object', 'return_path'):
                    argument = self.helper_argument(summary, value)
                    uid = self.object_uid(argument, state) if argument is not None else None
                    if uid is None and argument is not None:
                        uid = self.path_uid(argument, state)
                    if uid is not None:
                        binder = self.bind_object if kind == 'return_object' else self.bind_path
                        self.bind_targets(state, targets, binder, uid, node)
                        return

                if kind in ('close', 'consumes_path'):
                    binders = (
                        ('return_object_index', self.bind_object),
                        ('return_path_index', self.bind_path),
                    )
                    for key, binder in binders:
                        index = summary.get(key)
                        if index is None or index >= len(value.args):
                            continue
                        argument = value.args[index]
                        uid = self.object_uid(argument, state)
                        if uid is None:
                            uid = self.path_uid(argument, state)
                        if uid is not None:
                            self.bind_targets(state, targets, binder, uid, node)
                            return

            self.unbind_targets(state, targets, node)
            return

        self.eval_expr(value, state)

        uid = None
        binder = None
        if isinstance(value, (ast.Name, ast.Attribute)):
            uid = self.object_uid(value, state)
            if uid is not None:
                binder = self.bind_object
            else:
                uid = self.path_uid(value, state)
                if uid is not None:
                    binder = self.bind_path

        if uid is not None and binder is not None:
            self.bind_targets(state, targets, binder, uid, node)
            return

        self.unbind_targets(state, targets, node)

    def exec_unpack(self, target, value, state, node):
        target_children = list(target.elts)
        value_children = list(value.elts)

        creation = None
        if isinstance(value, (ast.Tuple, ast.List)) or len(value_children) != 1:
            creation = None
        if len(value_children) == 1 and isinstance(value_children[0], ast.Call):
            creation = self.creation_info(value_children[0])

        if creation is not None and creation['returns'] == 'tuple':
            call = value_children[0]
            for argument in call.args:
                self.eval_expr(argument, state)
            for keyword in call.keywords:
                self.eval_expr(keyword.value, state)
            self.exec_mkstemp_assign(target_children, call, creation, state, node)
            return

        for index, target_child in enumerate(target_children):
            if index < len(value_children):
                self.bind_single(target_child, value_children[index], state, node)
            else:
                self.unbind_targets(state, [target_child], node)

    def bind_single(self, target, value, state, node):
        self.eval_expr(value, state)

        uid = self.object_uid(value, state)
        if uid is not None:
            self.bind_targets(state, [target], self.bind_object, uid, node)
            return

        uid = self.path_uid(value, state)
        if uid is not None:
            self.bind_targets(state, [target], self.bind_path, uid, node)
            return

        self.unbind_targets(state, [target], node)

    def exec_mkstemp_assign(self, targets, call, creation, state, node):
        targets = list(targets)
        if len(targets) == 1 and isinstance(targets[0], (ast.Tuple, ast.List)):
            targets = list(targets[0].elts)

        uid = self.new_token(
            state,
            creation['name'],
            creation['delete'],
            creation['persistent'],
            node,
        )

        # mkstemp returns `(fd, path)`. The descriptor owns the open handle,
        # while the path is already persistent. Both alias the same token.
        if len(targets) > 0:
            self.bind_targets(state, [targets[0]], self.bind_object, uid, node)
        if len(targets) > 1:
            for target in targets[1:]:
                self.bind_targets(state, [target], self.bind_path, uid, node)

    def exec_with(self, node, state):
        exit_uids = []

        for item in node.items:
            value = item.context_expr
            uid = None
            creation = self.creation_info(value) if isinstance(value, ast.Call) else None
            effect, extra = ((-1, None) if creation is not None
                             else self.classify_call(value)) if isinstance(value, ast.Call) else (-1, None)

            if creation is not None:
                for argument in value.args:
                    self.eval_expr(argument, state)
                for keyword in value.keywords:
                    self.eval_expr(keyword.value, state)
                uid = self.new_token(
                    state,
                    creation['name'],
                    creation['delete'],
                    creation['persistent'],
                    value,
                )
            elif effect == 'helper' and extra['kind'] == 'factory':
                creation = self.factory_creation(extra, value)
                uid = self.new_token(
                    state,
                    creation['name'],
                    creation['delete'],
                    creation['persistent'],
                    value,
                )
            else:
                uid = self.object_uid(value, state)
                if uid is None and isinstance(value, ast.Call):
                    uid = self.with_closing_uid(value, state)
                if uid is None:
                    self.eval_expr(value, state)

            if item.optional_vars is not None:
                if uid is not None:
                    self.bind_targets(
                        state,
                        [item.optional_vars],
                        self.bind_object,
                        uid,
                        node,
                    )
                else:
                    self.unbind_targets(state, [item.optional_vars], node)

            if uid is not None:
                exit_uids.append(uid)

        self.exec_body(node.body, state)

        for uid in exit_uids:
            self.mark_close(
                state,
                uid,
                node,
                'temporary object exited its context manager',
            )

    def with_closing_uid(self, call, state):
        if not self.matches_module_function(call.func, 'contextlib.closing'):
            return None
        if not call.args:
            return None
        return self.object_uid(call.args[0], state)

    def exec_if(self, node, state):
        self.eval_expr(node.test, state)

        body_state = state.clone()
        body_terminates = self.exec_body(node.body, body_state)

        if node.orelse:
            else_state = state.clone()
            else_terminates = self.exec_body(node.orelse, else_state)
        else:
            else_state = state.clone()
            else_terminates = False

        if body_terminates and else_terminates:
            merged = _merge_states(body_state, else_state, node)
            self.replace_state(state, merged)
            return True
        if body_terminates:
            self.replace_state(state, else_state)
            return False
        if else_terminates:
            self.replace_state(state, body_state)
            return False

        merged = _merge_states(body_state, else_state, node)
        self.replace_state(state, merged)
        return False

    def exec_loop(self, node, state):
        if isinstance(node, ast.For):
            self.eval_expr(node.iter, state)
        else:
            self.eval_expr(node.test, state)

        body_state = state.clone()
        if isinstance(node, ast.For):
            self.unbind_targets(body_state, [node.target], node)

        self.exec_body(node.body, body_state)
        merged = _merge_states(state, body_state, node)

        if node.orelse:
            self.exec_body(node.orelse, merged)

        self.replace_state(state, merged)

    def exec_try(self, node, state):
        body_state = state.clone()
        body_terminates = self.exec_body(node.body, body_state)

        if node.orelse and not body_terminates:
            body_terminates = self.exec_body(node.orelse, body_state)

        continuing = []
        if not body_terminates:
            continuing.append(body_state)

        all_handlers_terminate = True
        for handler in node.handlers:
            handler_state = state.clone()
            handler_terminates = self.exec_body(handler.body, handler_state)
            if not handler_terminates:
                continuing.append(handler_state)
                all_handlers_terminate = False

        if continuing:
            merged = continuing[0]
            for next_state in continuing[1:]:
                merged = _merge_states(merged, next_state, node)
        else:
            merged = body_state

        final_terminates = False
        if node.finalbody:
            final_terminates = self.exec_body(node.finalbody, merged)

        self.replace_state(state, merged)

        return final_terminates or (body_terminates and all_handlers_terminate)

    @staticmethod
    def replace_state(target, source):
        target.tokens = source.tokens
        target.objects = source.objects
        target.paths = source.paths


class BadTempfileIdentityUseLinter(base.BaseLinter):
    """Tracks temporary-file path identity through close and context exit.

    A temporary file's name is only known to identify the created object
    while that object still owns the path. This linter follows temporary
    file objects and path aliases through the small, explainable subset of
    same-module helper functions below. Unknown calls form an analysis
    boundary rather than being assumed safe.
    """

    off_by_default = False

    _code = 'DUO139'
    _error_tmpl = (
        'DUO139 temporary file path used after identity is no longer guaranteed'
    )

    def __init__(self, *args, **kwargs):
        self.boundaries = []
        self._summaries = {}
        self._uid_counter = itertools.count(1)

        super(BadTempfileIdentityUseLinter, self).__init__(*args, **kwargs)

    def get_results(self):
        seen = set()
        results = []
        for result in sorted(
                self.results,
                key=lambda item: (item.lineno, item.col_offset, item.message)):
            key = (result.lineno, result.col_offset, result.message)
            if key in seen:
                continue
            seen.add(key)
            results.append(result)
        return results

    def visit_Module(self, node):
        self._summary_analyzer = _ScopeAnalyzer(
            self,
            {},
            self._uid_counter,
        )
        self._summaries = self.collect_summaries(node)

        analyzer = _ScopeAnalyzer(
            self,
            self._summaries,
            self._uid_counter,
        )
        analyzer.analyze(node.body)

        scopes = (ast.FunctionDef, ast.ClassDef)
        async_function_def = getattr(ast, 'AsyncFunctionDef', None)
        if async_function_def is not None:
            scopes = scopes + (async_function_def,)

        for child in ast.walk(node):
            if child is node or not isinstance(child, scopes):
                continue
            analyzer.analyze(child.body)

    def creation_info(self, call):
        return self._summary_analyzer.creation_info(call)

    def matches_module_function(self, func, canonical):
        return self._summary_analyzer.matches_module_function(
            func,
            canonical,
        )

    def collect_summaries(self, module_node):
        summaries = {}
        function_defs = (ast.FunctionDef,)
        async_function_def = getattr(ast, 'AsyncFunctionDef', None)

        for statement in module_node.body:
            if isinstance(statement, function_defs):
                summary = self.summarize_function(statement)
                if summary is not None:
                    summaries[statement.name] = summary
            elif (async_function_def is not None
                    and isinstance(statement, async_function_def)):
                continue

        return summaries

    def summarize_function(self, function):
        if function.decorator_list:
            return None
        if function.args.vararg or function.args.kwarg:
            return None
        if getattr(function.args, 'kwonlyargs', None):
            return None

        parameters = [argument.arg for argument in function.args.args]
        if not parameters:
            return self.summarize_factory(function, parameters)

        roles = collections.defaultdict(set)
        factory = None
        return_object = None
        return_path = None

        for statement in function.body:
            if isinstance(statement, ast.Pass):
                continue
            if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Str):
                continue

            if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
                self.summarize_helper_call(
                    statement.value,
                    parameters,
                    roles,
                )
                continue

            if isinstance(statement, ast.Assign):
                for parameter in parameters:
                    if (self.name_used(statement.value, parameter)
                            or any(self.name_used(target, parameter)
                                   for target in statement.targets)):
                        return None
                continue

            if isinstance(statement, ast.Return):
                value = statement.value
                if value is None:
                    continue
                creation = self.creation_info(value) if isinstance(value, ast.Call) else None
                if creation is not None:
                    factory = creation
                    continue
                if isinstance(value, ast.Name) and value.id in parameters:
                    return_object = value.id
                    continue
                if (isinstance(value, ast.Attribute)
                        and value.attr == 'name'
                        and isinstance(value.value, ast.Name)
                        and value.value.id in parameters):
                    return_path = value.value.id
                    continue
                if isinstance(value, ast.Call):
                    if self.call_is_benign(value, parameters):
                        continue
                if any(self.name_used(value, parameter) for parameter in parameters):
                    return None
                continue

            if isinstance(statement, (ast.With, _ASYNC_WITH)):
                self.summarize_helper_with(statement, parameters, roles)
                continue

            if isinstance(statement, ast.If):
                self.summarize_helper_expression(statement.test, parameters, roles)
                self.summarize_helper_body(statement.body, parameters, roles)
                self.summarize_helper_body(statement.orelse, parameters, roles)
                continue

            if isinstance(statement, (ast.For, ast.While, _ASYNC_FOR)):
                if isinstance(statement, ast.For):
                    self.summarize_helper_expression(statement.iter, parameters, roles)
                    for parameter in parameters:
                        if self.name_used(statement.target, parameter):
                            roles[parameter].add('unknown')
                elif isinstance(statement, _ASYNC_FOR):
                    self.summarize_helper_expression(statement.iter, parameters, roles)
                    for parameter in parameters:
                        if self.name_used(statement.target, parameter):
                            roles[parameter].add('unknown')
                else:
                    self.summarize_helper_expression(statement.test, parameters, roles)
                self.summarize_helper_body(statement.body, parameters, roles)
                self.summarize_helper_body(statement.orelse, parameters, roles)
                continue

            if isinstance(statement, ast.Try):
                self.summarize_helper_body(statement.body, parameters, roles)
                for handler in statement.handlers:
                    self.summarize_helper_body(handler.body, parameters, roles)
                self.summarize_helper_body(statement.orelse, parameters, roles)
                self.summarize_helper_body(statement.finalbody, parameters, roles)
                continue

            return None

        salient = []
        for parameter in parameters:
            parameter_roles = roles.get(parameter, set())
            if 'close' in parameter_roles:
                salient.append(('close', parameter))
            elif 'consumes_path' in parameter_roles:
                salient.append(('consumes_path', parameter))
            elif 'unknown' in parameter_roles:
                return None

        if sum(1 for role, unused in salient if role in ('close', 'consumes_path')) > 1:
            return None

        if factory is not None:
            return {
                'kind': 'factory',
                'creation': factory,
                'parameters': parameters,
            }

        if salient:
            kind, parameter = salient[0]
            summary = {
                'kind': kind,
                'param': parameter,
                'index': parameters.index(parameter),
            }
            if return_object is not None:
                summary['return_object_index'] = parameters.index(return_object)
            if return_path is not None:
                summary['return_path_index'] = parameters.index(return_path)
            return summary

        if return_object is not None:
            return {
                'kind': 'return_object',
                'param': return_object,
                'index': parameters.index(return_object),
            }

        if return_path is not None:
            return {
                'kind': 'return_path',
                'param': return_path,
                'index': parameters.index(return_path),
            }

        return {'kind': 'benign'}

    def summarize_helper_with(self, statement, parameters, roles):
        for item in statement.items:
            context = item.context_expr
            if isinstance(context, ast.Call):
                self.summarize_helper_call(context, parameters, roles)
            else:
                for parameter in parameters:
                    if self.name_used(context, parameter):
                        roles[parameter].add('close')
            if item.optional_vars is not None:
                for parameter in parameters:
                    if self.name_used(item.optional_vars, parameter):
                        roles[parameter].add('unknown')
        self.summarize_helper_body(statement.body, parameters, roles)

    def summarize_helper_body(self, body, parameters, roles):
        for statement in body:
            if isinstance(statement, ast.Pass):
                continue
            if isinstance(statement, ast.Expr):
                if isinstance(statement.value, ast.Str):
                    continue
                if isinstance(statement.value, ast.Call):
                    self.summarize_helper_call(
                        statement.value,
                        parameters,
                        roles,
                    )
                else:
                    self.summarize_helper_expression(
                        statement.value,
                        parameters,
                        roles,
                    )
                continue
            if isinstance(statement, ast.Assign):
                for parameter in parameters:
                    if any(self.name_used(target, parameter)
                           for target in statement.targets):
                        roles[parameter].add('unknown')
                    elif self.name_used(statement.value, parameter):
                        if isinstance(statement.value, ast.Call):
                            self.summarize_helper_call(
                                statement.value,
                                parameters,
                                roles,
                            )
                        else:
                            roles[parameter].add('benign')
                continue
            if isinstance(statement, ast.Return):
                if statement.value is not None:
                    self.summarize_helper_expression(
                        statement.value,
                        parameters,
                        roles,
                    )
                continue
            if isinstance(statement, (ast.With, _ASYNC_WITH)):
                self.summarize_helper_with(statement, parameters, roles)
                continue
            if isinstance(statement, ast.If):
                self.summarize_helper_expression(statement.test, parameters, roles)
                self.summarize_helper_body(statement.body, parameters, roles)
                self.summarize_helper_body(statement.orelse, parameters, roles)
                continue
            if isinstance(statement, ast.Try):
                self.summarize_helper_body(statement.body, parameters, roles)
                for handler in statement.handlers:
                    self.summarize_helper_body(handler.body, parameters, roles)
                self.summarize_helper_body(statement.orelse, parameters, roles)
                self.summarize_helper_body(statement.finalbody, parameters, roles)
                continue
            for parameter in parameters:
                if self.name_used(statement, parameter):
                    roles[parameter].add('unknown')

    def summarize_helper_expression(self, node, parameters, roles):
        if node is None:
            return
        if isinstance(node, ast.Call):
            self.summarize_helper_call(node, parameters, roles)
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.Call):
                self.summarize_helper_call(child, parameters, roles)
            elif isinstance(child, ast.expr):
                self.summarize_helper_expression(child, parameters, roles)

    def summarize_factory(self, function, parameters):
        created = {}

        for statement in function.body:
            if isinstance(statement, ast.Pass):
                continue
            if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Str):
                continue

            if isinstance(statement, ast.Assign):
                if not isinstance(statement.value, ast.Call):
                    return None
                creation = self.creation_info(statement.value)
                if creation is None:
                    return None
                for target in statement.targets:
                    if not isinstance(target, ast.Name):
                        return None
                    created[target.id] = creation
                continue

            if isinstance(statement, ast.Return):
                value = statement.value
                if isinstance(value, ast.Call):
                    creation = self.creation_info(value)
                    if creation is not None:
                        return {
                            'kind': 'factory',
                            'creation': creation,
                        }
                    return None
                if isinstance(value, ast.Name) and value.id in created:
                    return {
                        'kind': 'factory',
                        'creation': created[value.id],
                        'parameters': parameters,
                    }
                return None

            return None

        return None

    def summarize_helper_call(self, call, parameters, roles):
        for parameter in parameters:
            if (isinstance(call.func, ast.Attribute)
                    and isinstance(call.func.value, ast.Name)
                    and call.func.value.id == parameter):
                attribute = call.func.attr
                if attribute in _CLOSE_METHODS or attribute in _FORCED_CLOSE_METHODS:
                    roles[parameter].add('close')
                elif attribute in _BENIGN_OBJECT_METHODS:
                    roles[parameter].add('benign')
                else:
                    roles[parameter].add('unknown')
                continue

            if (isinstance(call.func, ast.Attribute)
                    and self.name_used(call.func.value, parameter)):
                if self.call_consumes_path(call):
                    roles[parameter].add('consumes_path')
                elif self.call_is_benign(call, parameters):
                    roles[parameter].add('benign')
                else:
                    roles[parameter].add('unknown')
                continue

            if not any(self.name_used(argument, parameter)
                       for argument in call.args + [
                           keyword.value for keyword in call.keywords
                       ]):
                continue

            if self.call_consumes_path(call):
                roles[parameter].add('consumes_path')
            elif self.call_is_benign(call, parameters):
                roles[parameter].add('benign')
            else:
                roles[parameter].add('unknown')

    def call_consumes_path(self, call):
        for canonical in _CONSUMING_PATH_FUNCTIONS:
            if self.matches_module_function(call.func, canonical):
                return True
        if (isinstance(call.func, ast.Attribute)
                and call.func.attr in _CONSUMING_PATH_METHODS):
            return True
        return False

    def call_is_benign(self, call, parameters):
        if isinstance(call.func, ast.Name) and call.func.id in _BENIGN_BUILTIN_CALLS:
            return True
        for canonical in _BENIGN_MODULE_FUNCTIONS:
            if self.matches_module_function(call.func, canonical):
                return True
        if isinstance(call.func, ast.Attribute):
            if (call.func.attr in _CONSUMING_PATH_METHODS
                    or call.func.attr in _CLOSE_METHODS
                    or call.func.attr in _FORCED_CLOSE_METHODS):
                return False
            if isinstance(call.func.value, ast.Call):
                return self.call_is_benign(call.func.value, parameters)
            if (isinstance(call.func.value, ast.Name)
                    and call.func.value.id in parameters):
                return call.func.attr in _BENIGN_OBJECT_METHODS
        return False

    def name_used(self, node, name):
        return any(
            isinstance(child, ast.Name) and child.id == name
            for child in ast.walk(node)
        )


# Compatibility aliases: the rule has been described both in terms of
# "identity" and in terms of the "path" obtained from a temporary file.
BadTempfilePathUseLinter = BadTempfileIdentityUseLinter
BadTempfileNameUseLinter = BadTempfileIdentityUseLinter
BadTempfileOwnershipUseLinter = BadTempfileIdentityUseLinter
TempfileIdentityUseLinter = BadTempfileIdentityUseLinter
