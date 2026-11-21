#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast

from . import base


_HASH_CONSTRUCTORS = frozenset([
    'blake2b',
    'blake2s',
    'md5',
    'sha1',
    'sha224',
    'sha256',
    'sha384',
    'sha512',
    'sha3_224',
    'sha3_256',
    'sha3_384',
    'sha3_512',
    'shake_128',
    'shake_256',
])

_DIRECT_DIGEST_FUNCTIONS = frozenset([
    'crc32',
    'crc_hqx',
    'pbkdf2_hmac',
])

_DIGEST_METHODS = frozenset([
    'b64digest',
    'digest',
    'hexdigest',
])

_HASH_BUILDER_FACTORIES = frozenset([
    'new',
])


class _Source(object):
    def __init__(self, key, name, is_artifact=False, is_parameter=False):
        self.key = key
        self.name = name
        self.is_artifact = is_artifact
        self.is_parameter = is_parameter

    def __hash__(self):
        return hash(self.key)

    def __eq__(self, other):
        return isinstance(other, _Source) and self.key == other.key

    def __repr__(self):
        return self.name


class _HashBuilder(object):
    def __init__(self, name, inputs=frozenset()):
        self.name = name
        self.inputs = inputs


class _Value(object):
    def __init__(
        self,
        origins=frozenset(),
        digest_origins=frozenset(),
        callables=(),
        builder=None,
    ):
        self.origins = frozenset(origins)
        self.digest_origins = frozenset(digest_origins)
        self.callables = tuple(callables)
        self.builder = builder

    @classmethod
    def source(cls, source):
        return cls(origins=frozenset([source]))

    @classmethod
    def digest(cls, value):
        if not value.origins:
            return cls(digest_origins=frozenset([frozenset()]))
        return cls(
            origins=value.origins,
            digest_origins=frozenset([frozenset(value.origins)]),
        )

    def merged(self, other):
        if other is None:
            return self
        return _Value(
            origins=self.origins | other.origins,
            digest_origins=self.digest_origins | other.digest_origins,
            callables=self.callables + other.callables,
        )


class _Callable(object):
    def __init__(self, node, scope, env):
        self.node = node
        self.scope = scope
        self.env = env

    def __hash__(self):
        return hash(id(self.node))

    def __eq__(self, other):
        return isinstance(other, _Callable) and self.node is other.node


class _Scope(object):
    def __init__(self, node, parent, path):
        self.node = node
        self.parent = parent
        self.path = path
        self.functions = {}

    @property
    def name(self):
        return getattr(self.node, 'name', '')


class _Env(object):
    def __init__(self, scope, parent=None):
        self.scope = scope
        self.parent = parent
        self.values = {}

    def get(self, name):
        if name in self.values:
            return self.values[name]
        if self.parent is not None:
            return self.parent.get(name)
        return None

    def set(self, name, value):
        self.values[name] = value

    def copy(self):
        env = _Env(self.scope, self.parent)
        env.values = dict(self.values)
        return env

    def merge(self, other):
        for name, value in other.values.items():
            if name in self.values:
                self.values[name] = self.values[name].merged(value)
            else:
                self.values[name] = value


class _Context(object):
    def __init__(
        self,
        env,
        integrity_point=False,
        suppress_integrity=False,
        active=None,
        depth=0,
    ):
        self.env = env
        self.integrity_point = integrity_point
        self.suppress_integrity = suppress_integrity
        self.active = active if active is not None else set()
        self.depth = depth

    def child(self, env, integrity_point=None):
        return _Context(
            env=env,
            integrity_point=(
                self.integrity_point
                if integrity_point is None
                else integrity_point
            ),
            suppress_integrity=self.suppress_integrity,
            active=self.active,
            depth=self.depth,
        )


class DigestSourceMismatchLinter(base.BaseLinter):
    """Find integrity verification points that compare digests produced from
    different source objects.

    The linter is intentionally limited to locally-defined code. It follows
    plain assignments, returned/directly-called closures, and local function
    parameter bindings. Digests used only as cache keys or deduplication
    fingerprints are left alone because they never reach an integrity
    comparison point.

    ``original_parameters`` names parameters that hold the original artifact
    (for example ``content`` or ``body``). ``integrity_comparison_points``
    names calls/functions that claim to verify integrity (for example
    ``hmac.compare_digest`` or ``verify_digest``).
    """
    off_by_default = False

    _code = 'DUO139'
    _error_tmpl = 'DUO139 integrity check compares digests of different objects'

    original_parameters = frozenset([
        'artifact',
        'blob',
        'body',
        'content',
        'data',
        'file_data',
        'file_obj',
        'original',
        'payload',
    ])

    integrity_comparison_points = frozenset([
        'check_digest',
        'check_integrity',
        'compare_digest',
        'hmac.compare_digest',
        'secrets.compare_digest',
        'validate_digest',
        'validate_integrity',
        'verify_digest',
        'verify_integrity',
    ])

    digest_functions = frozenset()

    _original_aliases = (
        'original_parameter_names',
        'original_params',
        'artifact_parameters',
        'artifact_parameter_names',
        'artifact_params',
        'source_parameters',
        'source_parameter_names',
        'source_params',
        'content_parameters',
        'content_parameter_names',
        'content_params',
        'origin_parameters',
        'origin_parameter_names',
        'origin_params',
        'protected_parameters',
        'protected_parameter_names',
        'protected_params',
    )

    _comparison_aliases = (
        'integrity_comparison_point_names',
        'integrity_check_points',
        'integrity_check_functions',
        'integrity_checks',
        'integrity_points',
        'comparison_points',
        'comparison_point_names',
        'comparison_functions',
        'final_comparison_points',
        'verification_points',
        'verification_functions',
        'verify_functions',
        'sink_functions',
        'sinks',
    )

    _digest_aliases = (
        'digest_function_names',
        'digest_builders',
        'hash_functions',
        'hash_builders',
    )

    def __init__(
        self,
        original_parameters=None,
        integrity_comparison_points=None,
        digest_functions=None,
        **kwargs
    ):
        self._original_config = original_parameters
        self._comparison_config = integrity_comparison_points
        self._digest_config = digest_functions

        self.configure(**kwargs)
        self._sync_public_config()
        super(DigestSourceMismatchLinter, self).__init__()

    def configure(
        self,
        original_parameters=None,
        integrity_comparison_points=None,
        digest_functions=None,
        **kwargs
    ):
        if original_parameters is not None:
            self._original_config = original_parameters
        if integrity_comparison_points is not None:
            self._comparison_config = integrity_comparison_points
        if digest_functions is not None:
            self._digest_config = digest_functions

        for key, value in kwargs.items():
            if key in self._original_aliases or key == 'original_parameters':
                self._original_config = value
            elif key in self._comparison_aliases or key == 'integrity_comparison_points':
                self._comparison_config = value
            elif key in self._digest_aliases or key == 'digest_functions':
                self._digest_config = value

        self._sync_public_config()
        return self

    def _sync_public_config(self):
        if self._original_config is not None:
            self.original_parameters = self._original_config
        if self._comparison_config is not None:
            self.integrity_comparison_points = self._comparison_config
        if self._digest_config is not None:
            self.digest_functions = self._digest_config

    def get_results(self):
        return sorted(
            self.results,
            key=lambda result: (
                result.lineno,
                result.col_offset,
                result.message,
            ),
        )

    def visit_Module(self, node):
        if not self.namespace:
            from .. import namespace
            self.namespace = namespace.Namespace.from_module_node(node)

        self._scopes = {}
        self._results_seen = set()
        self._active_analyzed = set()
        self._module_env = _Env(_Scope(node, None, ''))
        self._build_scopes(node, self._module_env.scope)
        self._find_called_functions(node)
        self._bind_top_level_functions(self._module_env)
        self._walk_block(node.body, self._module_env, _Context(self._module_env))
        self._analyze_unbound_entries()

    def _build_scopes(self, node, scope):
        self._scopes[node] = scope

        for child in ast.iter_child_nodes(node):
            if isinstance(child, _function_types()):
                child_scope = _Scope(
                    child,
                    scope,
                    _join_path(scope.path, child.name),
                )
                scope.functions[child.name] = child_scope
                self._scopes[child] = child_scope
                self._build_scopes(child, child_scope)
            elif isinstance(child, ast.ClassDef):
                child_scope = _Scope(
                    child,
                    scope,
                    _join_path(scope.path, child.name),
                )
                self._scopes[child] = child_scope
                self._build_scopes(child, child_scope)
            else:
                self._build_scopes(child, scope)

    def _find_called_functions(self, node):
        self._called_function_ids = set()

        for scope_node, scope in self._scopes.items():
            if isinstance(scope_node, ast.Module):
                calls = self._calls_in_scope(scope_node.body)
            elif isinstance(scope_node, _function_types()):
                calls = self._calls_in_scope(scope_node.body)
            else:
                continue

            for call in calls:
                function = self._resolve_function(scope, call.func)
                if function is not None:
                    self._called_function_ids.add(id(function.node))

    def _calls_in_scope(self, body):
        calls = []

        def walk(node):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, _function_types()):
                    continue
                if isinstance(child, ast.ClassDef):
                    continue
                if isinstance(child, ast.Call):
                    calls.append(child)
                walk(child)

        for statement in body:
            if isinstance(statement, _function_types()):
                continue
            if isinstance(statement, ast.ClassDef):
                continue
            if isinstance(statement, ast.Call):
                calls.append(statement)
            walk(statement)

        return calls

    def _resolve_function(self, scope, function_node):
        if isinstance(function_node, ast.Name):
            name = function_node.id
        elif isinstance(function_node, ast.Attribute):
            name = function_node.attr
        else:
            return None

        current = scope
        while current is not None:
            if name in current.functions:
                return current.functions[name]
            current = current.parent

        if (
            isinstance(function_node, ast.Attribute)
            and isinstance(function_node.value, ast.Name)
        ):
            for candidate in self._scopes.values():
                if not isinstance(candidate.node, _function_types()):
                    continue
                if candidate.node.name != name:
                    continue
                if isinstance(candidate.parent.node, ast.ClassDef):
                    return candidate

        return None

    def _bind_top_level_functions(self, env):
        for name, function_scope in env.scope.functions.items():
            env.set(
                name,
                _Value(callables=(_Callable(function_scope.node, function_scope, env),)),
            )

    def _analyze_unbound_entries(self):
        for node, scope in list(self._scopes.items()):
            if not isinstance(node, _function_types()):
                continue
            if id(node) in self._called_function_ids:
                continue
            if not self._is_entry_scope(scope):
                continue
            self._run_function(scope, [], {}, _Context(self._module_env))

    def _is_entry_scope(self, scope):
        parent = scope.parent
        if parent is None:
            return False
        if isinstance(parent.node, ast.Module):
            return True
        return isinstance(parent.node, ast.ClassDef) and isinstance(
            parent.parent.node,
            ast.Module,
        )

    def _walk_block(self, statements, env, context):
        for statement in statements:
            self._walk_statement(statement, env, context)

    def _walk_statement(self, statement, env, context):
        if isinstance(statement, ast.Assign):
            value = self._eval(statement.value, context)
            for target in statement.targets:
                self._bind_target(target, value, env, context)
        elif isinstance(statement, _ast_types('AnnAssign')):
            value = (
                self._eval(statement.value, context)
                if statement.value is not None
                else _Value()
            )
            self._bind_target(statement.target, value, env, context)
        elif isinstance(statement, ast.AugAssign):
            value = self._eval(statement.value, context)
            current = self._target_value(statement.target, context)
            self._bind_target(statement.target, current.merged(value), env, context)
        elif isinstance(statement, ast.Expr):
            self._eval(statement.value, context)
        elif isinstance(statement, ast.Return):
            if statement.value is not None:
                self._eval(statement.value, context)
        elif isinstance(statement, ast.Assert):
            self._eval(statement.test, context)
        elif isinstance(statement, ast.If):
            self._eval(statement.test, context)
            self._walk_branches([statement.body, statement.orelse], env, context)
        elif isinstance(statement, ast.While):
            self._eval(statement.test, context)
            self._walk_branches([statement.body, statement.orelse], env, context)
        elif isinstance(statement, _for_types()):
            iter_value = self._eval(statement.iter, context)
            loop_env = env.copy()
            self._bind_target(statement.target, iter_value, loop_env, context)
            self._walk_block(statement.body, loop_env, context)
            self._walk_block(statement.orelse, loop_env, context)
            env.merge(loop_env)
        elif isinstance(statement, _try_types()):
            bodies = [
                statement.body,
                getattr(statement, 'orelse', []),
                getattr(statement, 'finalbody', []),
            ]
            bodies.extend(
                handler.body
                for handler in getattr(statement, 'handlers', [])
            )
            self._walk_branches(bodies, env, context)
        elif isinstance(statement, _with_types()):
            items = getattr(statement, 'items', None)
            if items is None:
                items = [(
                    statement.context_expr,
                    statement.optional_vars,
                )]
            else:
                items = [
                    (item.context_expr, item.optional_vars)
                    for item in items
                ]
            for context_expr, optional_vars in items:
                value = self._eval(context_expr, context)
                if optional_vars is not None:
                    self._bind_target(optional_vars, value, env, context)
            self._walk_block(statement.body, env, context)
        elif isinstance(statement, _function_types()):
            scope = self._scopes[statement]
            env.set(
                statement.name,
                _Value(callables=(_Callable(statement, scope, env),)),
            )
        elif isinstance(statement, ast.ClassDef):
            class_scope = self._scopes[statement]
            class_env = _Env(class_scope, env)
            for name, function_scope in class_scope.functions.items():
                class_env.set(
                    name,
                    _Value(
                        callables=(
                            _Callable(function_scope.node, function_scope, class_env),
                        )
                    ),
                )
            self._walk_block(statement.body, class_env, context)
        elif isinstance(statement, ast.Raise):
            exception = getattr(statement, 'exc', None)
            cause = getattr(statement, 'cause', None)
            if exception is not None:
                self._eval(exception, context)
            if cause is not None:
                self._eval(cause, context)
        elif isinstance(statement, ast.Delete):
            for target in statement.targets:
                self._eval(target, context)
        elif isinstance(statement, _ast_types('Global', 'Nonlocal')):
            pass

    def _walk_branches(self, bodies, env, context):
        merged = env.copy()
        for body in bodies:
            branch_env = env.copy()
            self._walk_block(body, branch_env, context)
            merged.merge(branch_env)
        env.values = merged.values

    def _bind_target(self, target, value, env, context):
        if isinstance(target, ast.Name):
            env.set(
                target.id,
                self._named_value(target.id, env.scope, value),
            )
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._bind_target(element, value, env, context)
            return
        if isinstance(target, _ast_types('Starred')):
            self._bind_target(target.value, value, env, context)
            return
        if isinstance(target, ast.Attribute):
            receiver = self._eval(target.value, context)
            builder = self._builder_for_hash_object(receiver, target.attr)
            if builder is not None and isinstance(target.value, ast.Name):
                env.set(
                    target.value.id,
                    _Value(origins=receiver.origins, builder=builder),
                )
            return
        if isinstance(target, ast.Subscript):
            self._eval(target.value, context)
            self._eval(target.slice, context)

    def _named_value(self, name, scope, value):
        if (
            value.origins
            or value.digest_origins
            or value.callables
            or value.builder is not None
        ):
            return value
        return _Value.source(self._source_for_name(scope, name))

    def _target_value(self, target, context):
        if isinstance(target, ast.Name):
            value = context.env.get(target.id)
            if value is not None:
                return value
        return self._eval(target, context)

    def _eval(self, node, context):
        if node is None:
            return _Value()
        if isinstance(node, ast.Name):
            return self._eval_name(node, context)
        if isinstance(node, _constant_types()):
            return _Value()
        if isinstance(node, ast.Attribute):
            value = self._eval(node.value, context)
            return _Value(
                origins=value.origins,
                digest_origins=value.digest_origins,
            )
        if isinstance(node, ast.Subscript):
            value = self._eval(node.value, context)
            self._eval(node.slice, context)
            return _Value(
                origins=value.origins,
                digest_origins=value.digest_origins,
            )
        if isinstance(node, ast.Call):
            return self._eval_call(node, context)
        if isinstance(node, ast.BinOp):
            return self._eval(node.left, context).merged(
                self._eval(node.right, context)
            )
        if isinstance(node, ast.BoolOp):
            return self._merge_values(node.values, context)
        if isinstance(node, ast.Compare):
            left = self._eval(node.left, context)
            comparators = [self._eval(item, context) for item in node.comparators]
            integrity_compare = any(
                isinstance(operator, (ast.Eq, ast.NotEq))
                for operator in node.ops
            )
            if (
                integrity_compare
                and context.integrity_point
                and not context.suppress_integrity
            ):
                self._check_values([left] + comparators, node)
            result = left
            for item in comparators:
                result = result.merged(item)
            return _Value(origins=result.origins)
        if isinstance(node, ast.UnaryOp):
            return self._eval(node.operand, context)
        if isinstance(node, ast.IfExp):
            self._eval(node.test, context)
            return self._eval(node.body, context).merged(
                self._eval(node.orelse, context)
            )
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return self._merge_values(node.elts, context)
        if isinstance(node, ast.Dict):
            values = [
                self._eval(key, context)
                for key in node.keys
                if key is not None
            ]
            values.extend(self._eval(value, context) for value in node.values)
            return self._merge_value_list(values)
        if isinstance(node, ast.Lambda):
            scope = self._scope_for_lambda(node, context.env.scope)
            return _Value(
                callables=(_Callable(node, scope, context.env),)
            )
        if isinstance(node, _comprehension_types()):
            return self._eval_comprehension(node, context)
        if isinstance(node, _ast_types('Yield', 'YieldFrom')):
            return (
                self._eval(node.value, context)
                if node.value is not None
                else _Value()
            )
        if isinstance(node, _ast_types('Await')):
            return self._eval(node.value, context)
        if isinstance(node, _ast_types('Starred')):
            return self._eval(node.value, context)
        if isinstance(node, _ast_types('JoinedStr')):
            return self._merge_value_list(
                [
                    self._eval(value, context)
                    for value in node.values
                    if not isinstance(value, _constant_types())
                ] + [
                    self._eval(value.value, context)
                    for value in node.values
                    if isinstance(value, _ast_types('FormattedValue'))
                ]
            )
        if isinstance(node, _ast_types('FormattedValue')):
            return self._eval(node.value, context)
        if isinstance(node, _named_expr_types()):
            value = self._eval(node.value, context)
            if isinstance(node.target, ast.Name):
                context.env.set(node.target.id, value)
            return value

        values = []
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                values.append(self._eval(child, context))
        return self._merge_value_list(values)

    def _eval_name(self, node, context):
        value = context.env.get(node.id)
        if value is not None:
            return value

        scope = context.env.scope
        source = self._source_for_name(scope, node.id)
        value = _Value.source(source)
        context.env.set(node.id, value)
        return value

    def _source_for_name(self, scope, name):
        key = 'name:{}:{}'.format(scope.path, name)
        return _Source(
            key=key,
            name=name,
            is_artifact=self._is_original_name(scope, name, None),
            is_parameter=False,
        )

    def _eval_call(self, node, context):
        function_name = self._call_name(node.func)
        simple_name = _last_name(node.func)
        is_integrity_point = self._is_integrity_point(
            function_name,
            simple_name,
        )

        argument_values = [self._eval(argument, context) for argument in node.args]
        keyword_pairs = [
            (keyword.arg, self._eval(keyword.value, context))
            for keyword in node.keywords
        ]
        keyword_values = [value for name, value in keyword_pairs]
        all_arguments = argument_values + keyword_values

        if is_integrity_point and not context.suppress_integrity:
            self._check_values(all_arguments, node)

        receiver = None
        if isinstance(node.func, ast.Attribute):
            receiver = self._eval(node.func.value, context)

        builder = self._hash_result(node, all_arguments)
        if builder is not None:
            return _Value(
                origins=self._hash_inputs(node, all_arguments),
                builder=builder,
            )

        if isinstance(node.func, ast.Attribute) and receiver is not None:
            if node.func.attr in _DIGEST_METHODS and receiver.builder is not None:
                digest = _Value.digest(_Value(origins=receiver.builder.inputs))
                return _Value(
                    origins=digest.origins,
                    digest_origins=digest.digest_origins,
                )
            if node.func.attr == 'copy' and receiver.builder is not None:
                return _Value(
                    origins=receiver.origins,
                    builder=_HashBuilder(
                        receiver.builder.name,
                        receiver.builder.inputs,
                    ),
                )
            if node.func.attr == 'update' and receiver.builder is not None:
                inputs = receiver.builder.inputs
                for argument in argument_values:
                    inputs = inputs | argument.origins
                updated = _HashBuilder(receiver.builder.name, inputs)
                if isinstance(node.func.value, ast.Name):
                    context.env.set(
                        node.func.value.id,
                        _Value(origins=inputs, builder=updated),
                    )
                return _Value(origins=inputs, builder=updated)

        direct_digest = self._is_direct_digest_function(
            function_name,
            simple_name,
        )
        if direct_digest:
            return _Value.digest(self._merge_value_list(all_arguments))

        callables = []
        if isinstance(node.func, ast.Name):
            value = context.env.get(node.func.id)
            if value is not None:
                callables.extend(value.callables)
        if isinstance(node.func, ast.Attribute) and receiver is not None:
            callables.extend(receiver.callables)
        if not callables:
            function_scope = self._resolve_function(
                context.env.scope,
                node.func,
            )
            if function_scope is not None:
                class_env = context.env
                callables.append(
                    _Callable(function_scope.node, function_scope, class_env)
                )

        if callables:
            if context.depth >= 20:
                return self._merge_value_list(all_arguments)
            invoke_arguments = argument_values
            if (
                receiver is not None
                and isinstance(node.func, ast.Attribute)
                and any(
                    self._is_bound_method(callable_value)
                    for callable_value in callables
                )
            ):
                invoke_arguments = [receiver] + argument_values
            results = [
                self._invoke(
                    callable_value,
                    invoke_arguments,
                    keyword_pairs,
                    node,
                    context,
                    suppress_integrity=(
                        is_integrity_point or context.suppress_integrity
                    ),
                )
                for callable_value in callables
            ]
            return self._merge_value_list(results)

        merged = self._merge_value_list(all_arguments)
        if receiver is not None:
            merged = merged.merged(receiver)
        return _Value(
            origins=merged.origins,
            digest_origins=merged.digest_origins,
        )

    @staticmethod
    def _is_bound_method(callable_value):
        parent = callable_value.scope.parent
        return parent is not None and isinstance(parent.node, ast.ClassDef)

    def _invoke(
        self,
        callable_value,
        argument_values,
        keyword_pairs,
        call_node,
        context,
        suppress_integrity=False,
    ):
        function = callable_value.node
        identity = id(function)
        if identity in context.active:
            return _Value()

        context.active.add(identity)
        context.depth += 1
        try:
            env = _Env(callable_value.scope, callable_value.env)
            self._bind_parameters(
                function,
                callable_value.scope,
                argument_values,
                keyword_pairs,
                env,
                callable_value.env,
            )
            integrity_point = self._is_integrity_definition(
                function,
                callable_value.scope,
            )
            callee_context = _Context(
                env=env,
                integrity_point=integrity_point,
                suppress_integrity=suppress_integrity,
                active=context.active,
                depth=context.depth,
            )
            body = function.body
            if not isinstance(body, list):
                body = [ast.Return(value=body)]
            return self._run_body(body, env, callee_context)
        finally:
            context.depth -= 1
            context.active.remove(identity)

    def _run_function(self, scope, argument_values, keyword_pairs, context):
        function = scope.node
        identity = id(function)
        if identity in context.active:
            return _Value()

        context.active.add(identity)
        context.depth += 1
        try:
            env = _Env(scope, self._module_env)
            self._bind_parameters(
                function,
                scope,
                argument_values,
                keyword_pairs,
                env,
                self._module_env,
            )
            callee_context = _Context(
                env=env,
                integrity_point=self._is_integrity_definition(function, scope),
                suppress_integrity=context.suppress_integrity,
                active=context.active,
                depth=context.depth,
            )
            return self._run_body(function.body, env, callee_context)
        finally:
            context.depth -= 1
            context.active.remove(identity)

    def _run_body(self, body, env, context):
        self._walk_block(body, env, context)

        returns = []

        def collect(node):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, _function_types()):
                    continue
                if isinstance(child, ast.ClassDef):
                    continue
                if isinstance(child, ast.Return):
                    returns.append(
                        self._eval(child.value, context)
                        if child.value is not None
                        else _Value()
                    )
                collect(child)

        for statement in body:
            if isinstance(statement, ast.Return):
                returns.append(
                    self._eval(statement.value, context)
                    if statement.value is not None
                    else _Value()
                )
            collect(statement)

        return self._merge_value_list(returns)

    def _bind_parameters(
        self,
        function,
        scope,
        argument_values,
        keyword_pairs,
        env,
        defining_env,
    ):
        arguments = _argument_nodes(function)
        positional = [argument.arg for argument in arguments]
        keyword_map = {
            name: value
            for name, value in keyword_pairs
            if name is not None
        }

        for index, name in enumerate(positional):
            if index < len(argument_values):
                value = argument_values[index]
            elif name in keyword_map:
                value = keyword_map[name]
            else:
                value = self._parameter_default(
                    function,
                    index,
                    defining_env,
                )
            if value is None:
                value = _Value.source(
                    self._parameter_source(scope, name, index)
                )
            env.set(name, value)

        for index, name in enumerate(
            getattr(function.args, 'kwonlyargs', [])
        ):
            if name.arg in keyword_map:
                value = keyword_map[name.arg]
            else:
                value = self._parameter_default(
                    function,
                    len(positional) + index,
                    defining_env,
                )
            if value is None:
                value = _Value.source(
                    self._parameter_source(
                        scope,
                        name.arg,
                        len(positional) + index,
                    )
                )
            env.set(name.arg, value)

    def _parameter_default(self, function, index, defining_env):
        arguments = _argument_nodes(function)
        defaults = list(function.args.defaults)
        if not defaults:
            return None
        default_index = index - (len(arguments) - len(defaults))
        if default_index < 0 or default_index >= len(defaults):
            return None
        return self._eval(defaults[default_index], _Context(defining_env))

    def _parameter_source(self, scope, name, index):
        key = 'param:{}:{}:{}'.format(scope.path, index, name)
        return _Source(
            key=key,
            name=name,
            is_artifact=self._is_original_name(scope, name, index),
            is_parameter=True,
        )

    def _check_values(self, values, node):
        digests = []
        for value in values:
            for origins in value.digest_origins:
                if origins:
                    digests.append(origins)

        for index, left in enumerate(digests):
            for right in digests[index + 1:]:
                if not self._sources_mismatch(left, right):
                    continue
                message = self._mismatch_message(left, right)
                self._append_result(node, message)
                return

    def _sources_mismatch(self, left, right):
        left_artifacts = frozenset(
            source for source in left if source.is_artifact
        )
        right_artifacts = frozenset(
            source for source in right if source.is_artifact
        )

        if not left_artifacts and not right_artifacts:
            return False
        return left != right

    def _mismatch_message(self, left, right):
        return '{}: left digest derived from "{}"; right digest derived from "{}"'.format(
            self._error_tmpl,
            _sources_text(left),
            _sources_text(right),
        )

    def _append_result(self, node, message):
        key = (node.lineno, node.col_offset, message)
        if key in self._results_seen:
            return
        self._results_seen.add(key)
        self.results.append(
            base.Flake8Result(
                lineno=node.lineno,
                col_offset=node.col_offset,
                message=message,
            )
        )

    def _hash_result(self, node, values):
        if not isinstance(node.func, ast.Call) and not isinstance(
            node.func,
            (ast.Name, ast.Attribute),
        ):
            return None

        if isinstance(node.func, ast.Attribute) and node.func.attr in (
            _DIGEST_METHODS | frozenset(['update', 'copy'])
        ):
            return None

        function_name = self._call_name(node.func)
        simple_name = _last_name(node.func)
        if not self._is_hash_constructor(function_name, simple_name):
            return None

        return _HashBuilder(
            name=function_name or simple_name,
            inputs=self._hash_inputs(node, values),
        )

    def _hash_inputs(self, node, values):
        simple_name = _last_name(node.func)
        positional_count = len(node.args)
        positional_values = values[:positional_count]
        keyword_values = values[positional_count:]
        keyword_map = {
            keyword.arg: value
            for keyword, value in zip(node.keywords, keyword_values)
            if keyword.arg is not None
        }

        if simple_name == 'new':
            if self._is_hmac_new(node):
                value = keyword_map.get('msg')
            else:
                value = keyword_map.get('data') or keyword_map.get('string')
            if value is None and len(positional_values) > 1:
                value = positional_values[1]
            if value is None:
                return frozenset()
            return value.origins

        value = keyword_map.get('data') or keyword_map.get('string')
        if value is None and positional_values:
            value = positional_values[0]
        if value is None:
            return frozenset()
        return value.origins

    def _is_hmac_new(self, node):
        return self._call_name(node.func).endswith('hmac.new')

    def _builder_for_hash_object(self, value, attribute):
        if value.builder is not None:
            return value.builder
        return None

    def _is_hash_constructor(self, function_name, simple_name):
        names = _HASH_CONSTRUCTORS | _HASH_BUILDER_FACTORIES
        names = names | self._configured_names(
            'digest_functions',
            self._digest_aliases,
            self._digest_config,
            self.digest_functions,
        )
        return simple_name in names or function_name in names

    def _is_direct_digest_function(self, function_name, simple_name):
        names = _DIRECT_DIGEST_FUNCTIONS | self._configured_names(
            'digest_functions',
            self._digest_aliases,
            self._digest_config,
            self.digest_functions,
        )
        return simple_name in names or function_name in names

    def _is_original_name(self, scope, name, index):
        configuration = self._configured_names(
            'original_parameters',
            self._original_aliases,
            self._original_config,
            self.original_parameters,
        )
        if not configuration:
            return False

        return _config_matches(
            configuration,
            scope,
            name,
            index,
        )

    def _is_integrity_point(self, function_name, simple_name):
        configuration = self._configured_names(
            'integrity_comparison_points',
            self._comparison_aliases,
            self._comparison_config,
            self.integrity_comparison_points,
        )
        return _name_config_matches(configuration, function_name, simple_name)

    def _is_integrity_definition(self, function, scope):
        configuration = self._configured_names(
            'integrity_comparison_points',
            self._comparison_aliases,
            self._comparison_config,
            self.integrity_comparison_points,
        )
        function_name = getattr(function, 'name', 'lambda')
        if _name_config_matches(configuration, scope.path, function_name):
            return True
        for decorator in getattr(function, 'decorator_list', []):
            decorator_name = self._call_name(decorator)
            if _name_config_matches(
                configuration,
                decorator_name,
                _last_name(decorator),
            ):
                return True
        return False

    def _configured_names(self, canonical, aliases, explicit, default):
        if explicit is not None:
            return explicit

        instance = self.__dict__
        for name in aliases + (canonical,):
            if name in instance:
                return instance[name]

        for cls in type(self).__mro__:
            if cls is DigestSourceMismatchLinter:
                continue
            for name in aliases:
                if name in cls.__dict__:
                    return cls.__dict__[name]

        for cls in type(self).__mro__:
            if canonical in cls.__dict__:
                return cls.__dict__[canonical]

        return default

    def _call_name(self, node):
        if isinstance(node, ast.Call):
            return self._call_name(node.func)
        if isinstance(node, ast.Attribute):
            prefix = self._call_name(node.value)
            return _join_path(prefix, node.attr)
        if isinstance(node, ast.Name):
            return self._canonical_name(node.id)
        return ''

    def _canonical_name(self, name):
        asname = self.namespace.asname_to_name(name)
        if asname is not None:
            return asname

        for imported in self.namespace.from_imports:
            if not imported.module:
                continue
            for alias in imported.names:
                if alias.name == name or alias.asname == name:
                    return _join_path(imported.module, alias.name)

        return name

    def _scope_for_lambda(self, node, parent_scope):
        scope = _Scope(
            node,
            parent_scope,
            _join_path(parent_scope.path, 'lambda'),
        )
        self._scopes[node] = scope
        return scope

    def _eval_comprehension(self, node, context):
        values = []
        if isinstance(node, ast.DictComp):
            values.append(self._eval(node.key, context))
            values.append(self._eval(node.value, context))
        else:
            values.append(self._eval(node.elt, context))
        for generator in node.generators:
            values.append(self._eval(generator.iter, context))
            for condition in generator.ifs:
                values.append(self._eval(condition, context))
        return self._merge_value_list(values)

    def _merge_values(self, nodes, context):
        return self._merge_value_list(
            [self._eval(node, context) for node in nodes]
        )

    def _merge_value_list(self, values):
        result = _Value()
        for value in values:
            result = result.merged(value)
        return result


def _ast_types(*names):
    return tuple(
        getattr(ast, name)
        for name in names
        if hasattr(ast, name)
    )


def _function_types():
    types = (ast.FunctionDef,)
    if hasattr(ast, 'AsyncFunctionDef'):
        types += (ast.AsyncFunctionDef,)
    return types


def _for_types():
    types = (ast.For,)
    if hasattr(ast, 'AsyncFor'):
        types += (ast.AsyncFor,)
    return types


def _with_types():
    types = (ast.With,)
    if hasattr(ast, 'AsyncWith'):
        types += (ast.AsyncWith,)
    return types


def _try_types():
    return _ast_types('Try', 'TryExcept', 'TryFinally', 'TryStar')


def _comprehension_types():
    types = (
        ast.ListComp,
        ast.SetComp,
        ast.DictComp,
        ast.GeneratorExp,
    )
    return types


def _constant_types():
    if hasattr(ast, 'Constant'):
        return (ast.Constant,)
    return _ast_types('Str', 'Num', 'Bytes', 'NameConstant')


def _named_expr_types():
    if hasattr(ast, 'NamedExpr'):
        return (ast.NamedExpr,)
    return ()


def _argument_nodes(function):
    args = function.args
    positional = list(getattr(args, 'posonlyargs', [])) + list(args.args)
    return positional


def _join_path(prefix, name):
    if not prefix:
        return name
    return '{}.{}'.format(prefix, name)


def _last_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _last_name(node.func)
    return ''


def _sources_text(sources):
    return ', '.join(
        sorted(
            set(source.name for source in sources),
            key=lambda name: name,
        )
    )


def _config_entries(configuration):
    if configuration is None:
        return set()
    if isinstance(configuration, dict):
        entries = set()
        for value in configuration.values():
            entries |= _config_entries(value)
        return entries
    if isinstance(configuration, bool):
        return set()
    if isinstance(configuration, (str, int)):
        return set([configuration])
    try:
        return set(configuration)
    except TypeError:
        return set()


def _config_matches(configuration, scope, name, index):
    if configuration is True:
        return True
    if configuration is False or configuration is None:
        return False
    if isinstance(configuration, dict):
        for key, enabled in configuration.items():
            if not enabled:
                continue
            if isinstance(key, int) and index == key:
                return True
            if isinstance(key, str) and key == name:
                return True

        scope_names = [scope.path, getattr(scope.node, 'name', '')]
        scope_names.append(scope.path.split('.')[-1] if scope.path else '')
        for scope_name in scope_names:
            if scope_name in configuration:
                if _config_matches(
                    configuration[scope_name],
                    scope,
                    name,
                    index,
                ):
                    return True
        if '*' in configuration:
            return _config_matches(
                configuration['*'],
                scope,
                name,
                index,
            )
        return False

    for entry in _config_entries(configuration):
        if isinstance(entry, int) and index == entry:
            return True
        if isinstance(entry, str):
            if entry == name:
                return True
            if entry in (
                _join_path(scope.path, name),
                _join_path(getattr(scope.node, 'name', ''), name),
            ):
                return True
            if entry.endswith('.' + name):
                return True
    return False


def _name_config_matches(configuration, function_name, simple_name):
    entries = _config_entries(configuration)
    if isinstance(configuration, dict):
        entries |= set(
            key for key in configuration if isinstance(key, str)
        )

    for entry in entries:
        if not isinstance(entry, str):
            continue
        if entry in (function_name, simple_name):
            return True
        if entry.rsplit('.', 1)[-1] == simple_name:
            return True
        if function_name and function_name.endswith('.' + entry):
            return True
        if entry and function_name and entry.endswith('.' + function_name):
            return True
    return False


MismatchedDigestSourceLinter = DigestSourceMismatchLinter
BadDigestSourceUseLinter = DigestSourceMismatchLinter
