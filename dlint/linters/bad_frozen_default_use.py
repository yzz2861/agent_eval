#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast
import collections

from . import base
from .. import tree

_UNKNOWN = object()

_FUNCTION_DEFS = (ast.FunctionDef,) + (
    (ast.AsyncFunctionDef,) if hasattr(ast, 'AsyncFunctionDef') else ()
)

_FuncInfo = collections.namedtuple(
    '_FuncInfo',
    ['params', 'defaults']
)


class BadFrozenDefaultUseLinter(base.BaseLinter):
    """This linter flags calls to configured entry points that rely on an
    insecure default value for a configured switch keyword argument.

    Python captures default argument values when the "def" statement
    executes, not when the function is called. A naive check that resolves
    a name to its most recent assignment will miss wrappers whose default
    was frozen to an insecure value before the name was rebound:

        LEGACY_VERIFY = False

        def request(url, verify=LEGACY_VERIFY):  # frozen to False
            ...

        LEGACY_VERIFY = True  # rebinding does NOT thaw the default above

        request(url)  # still runs with verify=False

    This linter distinguishes those def-time ("frozen") defaults from
    configuration values supplied at the call site. Keyword-only
    parameters, rebinding of switch names, and forwarding calls between
    functions in the same module are all handled. Source files are never
    executed; only statically resolvable literals are considered.

    Engineers configure the rule with three class attributes:

    * "switch_kwargs": keyword argument names that act as security
      switches, e.g. ("verify",).
    * "entry_points": dotted paths of the functions whose calls should be
      checked, e.g. ("mymod.client.request",). A bare name such as
      "request" also matches attribute calls like "client.request".
    * "unsafe_values": literal values considered insecure, e.g. (False,).

    A call is only reported when its effective switch value provably
    equals one of the unsafe values: either an insecure literal is passed
    explicitly, or the switch is omitted and the callee's frozen default
    is insecure. An explicitly supplied safe value overrides the frozen
    default. Calls whose value cannot be determined statically (unknown
    provenance, e.g. "verify=get_config()" or a parameter without a
    default) remain unknown and are not reported.
    """
    off_by_default = False

    _code = 'DUO139'
    _error_tmpl = 'DUO139 call relies on an insecure frozen default for a configured switch'

    switch_kwargs = ()
    entry_points = ()
    unsafe_values = (False,)

    def __init__(self, *args, **kwargs):
        self._func_defs = {}
        self._module_env = {}

        super(BadFrozenDefaultUseLinter, self).__init__(*args, **kwargs)

    def visit_Module(self, node):
        if not self.switch_kwargs or not self.entry_points:
            return

        self._collect_module_definitions(node)
        self._check_statements(node.body, {})

    def _collect_module_definitions(self, module_node):
        env = {}

        for statement in module_node.body:
            if isinstance(statement, _FUNCTION_DEFS):
                self._func_defs[statement.name] = _FuncInfo(
                    params=self._param_names(statement),
                    defaults=self._freeze_defaults(statement, env),
                )
            else:
                self._update_env(statement, env)

        self._module_env = env

    def _param_names(self, function_def):
        args = function_def.args

        return (
            [arg.arg for arg in args.args]
            + [arg.arg for arg in args.kwonlyargs]
        )

    def _freeze_defaults(self, function_def, env):
        args = function_def.args
        defaults = {}

        positional_with_defaults = args.args[len(args.args) - len(args.defaults):]
        for arg, default in zip(positional_with_defaults, args.defaults):
            defaults[arg.arg] = self._static_value(default, env)

        for arg, default in zip(args.kwonlyargs, args.kw_defaults):
            if default is not None:
                defaults[arg.arg] = self._static_value(default, env)

        return defaults

    def _update_env(self, statement, env):
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    env[target.id] = self._static_value(statement.value, env)
        elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
            if isinstance(statement.target, ast.Name):
                env[statement.target.id] = self._static_value(statement.value, env)
        elif isinstance(statement, ast.AugAssign):
            if isinstance(statement.target, ast.Name):
                env[statement.target.id] = _UNKNOWN

    def _static_value(self, expression, env):
        if isinstance(expression, ast.Name):
            return env.get(expression.id, _UNKNOWN)

        try:
            return ast.literal_eval(expression)
        except (ValueError, SyntaxError, TypeError):
            return _UNKNOWN

    def _check_statements(self, statements, env):
        for statement in statements:
            self._check_statement(statement, env)

    def _check_statement(self, statement, env):
        for child in ast.iter_child_nodes(statement):
            if isinstance(child, ast.stmt) or isinstance(child, _FUNCTION_DEFS + (ast.ClassDef, ast.Lambda)):
                continue
            if isinstance(child, ast.Call):
                self._check_call(child, env)
            for call in self._find_calls(child):
                self._check_call(call, env)

        if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            self._update_env(statement, env)
        elif isinstance(statement, _FUNCTION_DEFS):
            self._check_function_def(statement, env)
        else:
            for child in ast.iter_child_nodes(statement):
                if isinstance(child, ast.stmt):
                    self._check_statement(child, env)

    def _check_function_def(self, function_def, env):
        func_info = self._func_defs.get(function_def.name)

        if func_info is not None:
            defaults = func_info.defaults
            params = func_info.params
        else:
            defaults = self._freeze_defaults(function_def, env)
            params = self._param_names(function_def)

        function_env = dict(self._module_env)
        for param in params:
            function_env[param] = defaults.get(param, _UNKNOWN)

        self._check_statements(function_def.body, function_env)

    def _find_calls(self, node):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, _FUNCTION_DEFS + (ast.ClassDef, ast.Lambda)):
                continue
            if isinstance(child, ast.Call):
                yield child
            for call in self._find_calls(child):
                yield call

    def _is_entry_point(self, module_path):
        return any(
            module_path == entry_point
            or module_path.endswith('.' + entry_point)
            for entry_point in self.entry_points
        )

    def _check_call(self, call, env):
        if not isinstance(call.func, (ast.Attribute, ast.Name)):
            return

        module_path = tree.module_path_str(call.func)

        if not module_path or not self._is_entry_point(module_path):
            return

        for switch_kwarg in self.switch_kwargs:
            value = self._effective_value(call, module_path, switch_kwarg, env)

            if value is not _UNKNOWN and value in self.unsafe_values:
                self.results.append(
                    base.Flake8Result(
                        lineno=call.lineno,
                        col_offset=call.col_offset,
                        message=self._error_tmpl
                    )
                )
                break

    def _effective_value(self, call, module_path, switch_kwarg, env):
        for keyword in call.keywords:
            if keyword.arg == switch_kwarg:
                return self._static_value(keyword.value, env)

        if any(keyword.arg is None for keyword in call.keywords):
            # '**kwargs' forwarding makes the provenance unknowable
            return _UNKNOWN

        if any(isinstance(arg, ast.Starred) for arg in call.args):
            # '*args' forwarding makes positional mapping unknowable
            return _UNKNOWN

        func_info = self._func_defs.get(module_path.split('.')[-1])

        if func_info is not None and call.args:
            for param, arg in zip(func_info.params, call.args):
                if param == switch_kwarg:
                    return self._static_value(arg, env)

        if func_info is not None and switch_kwarg in func_info.defaults:
            return func_info.defaults[switch_kwarg]

        return _UNKNOWN
