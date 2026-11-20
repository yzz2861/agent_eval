#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast
import json
import os

from . import base

from .. import tree

try:
    string_types = (basestring,)  # noqa: F821
except NameError:
    string_types = (str,)


class _Unknown(object):
    pass


class _DictValue(object):
    """A dictionary value with the key information needed by this rule."""

    def __init__(self, keys=(), unknown_keys=False):
        self.keys = set(keys)
        self.unknown_keys = unknown_keys
        self.removed = set()
        self.last_add = {}
        self.origins = {}

    def clone(self):
        value = _DictValue(self.keys, self.unknown_keys)
        value.removed = set(self.removed)
        value.last_add = dict(self.last_add)
        value.origins = dict(self.origins)
        return value

    def add(self, key, node=None, initial=False, refresh=False):
        key = str(key)
        if key not in self.keys:
            self.keys.add(key)
            if node is not None:
                self.last_add[key] = node
                self.origins[key] = node
        elif refresh and node is not None:
            self.last_add[key] = node
            self.origins[key] = node
        self.removed.discard(key)

    def remove(self, key, sensitive_keys):
        key = str(key)
        was_present = key in self.keys or self.unknown_keys
        self.keys.discard(key)
        self.last_add.pop(key, None)
        self.origins.pop(key, None)
        if was_present and key in sensitive_keys:
            self.removed.add(key)


class _Union(object):
    def __init__(self, values):
        self.values = []
        seen = set()
        for value in values:
            inner = value.values if isinstance(value, _Union) else (value,)
            for item in inner:
                marker = id(item)
                if marker not in seen:
                    seen.add(marker)
                    self.values.append(item)

    def clone(self, memo=None):
        memo = memo if memo is not None else {}
        return _Union(
            _clone_value(value, memo) for value in self.values
        )


_UNKNOWN = _Unknown()


def _clone_value(value, memo):
    if isinstance(value, _DictValue):
        marker = id(value)
        if marker not in memo:
            memo[marker] = value.clone()
        return memo[marker]
    if isinstance(value, _Union):
        return _Union(_clone_value(item, memo) for item in value.values)
    return value


def _iter_dicts(value):
    values = value.values if isinstance(value, _Union) else (value,)
    for item in values:
        if isinstance(item, _DictValue):
            yield item


def _union(values):
    flat = []
    for value in values:
        if isinstance(value, _Union):
            flat.extend(value.values)
        elif value is not None:
            flat.append(value)
    if not flat:
        return _UNKNOWN
    return flat[0] if len(flat) == 1 else _Union(flat)


class _Env(object):
    def __init__(self, values=None, writes=None):
        self.values = dict(values or {})
        self.writes = set(writes or ())

    def get(self, name, default=_UNKNOWN):
        return self.values.get(name, default)

    def set(self, name, value):
        self.values[name] = value
        self.writes.add(name)

    def clone(self):
        memo = {}
        return _Env(
            {
                name: _clone_value(value, memo)
                for name, value in self.values.items()
            }
        )

    def mark_aliases(self, value):
        for name, inner in self.values.items():
            if inner is value:
                self.writes.add(name)
                continue
            if isinstance(value, _Union) and inner in value.values:
                self.writes.add(name)
                continue
            if isinstance(inner, _Union) and value in inner.values:
                self.writes.add(name)


def _split_strings(value):
    if value is None:
        return []
    if isinstance(value, string_types):
        value = value.strip()
        if not value:
            return []
        if value.startswith("["):
            try:
                parsed = json.loads(value)
            except ValueError:
                parsed = None
            if isinstance(parsed, list):
                return _split_strings(parsed)
        return [
            item.strip()
            for item in value.replace("\n", ",").split(",")
            if item.strip()
        ]
    if isinstance(value, dict):
        return [str(item) for item in value]
    if isinstance(value, (list, tuple, set, frozenset)):
        result = []
        for item in value:
            result.extend(_split_strings(item))
        return result
    return [str(value)]


def _normalize_path(path):
    return str(path).strip().replace(":", ".")


def _load_config_blob(value):
    value = value.strip()
    if not value:
        return None
    if value.startswith("{"):
        try:
            return json.loads(value)
        except ValueError:
            return None
    path = value[1:] if value.startswith("@") else value
    try:
        with open(path) as fd:
            return json.load(fd)
    except (IOError, OSError, ValueError):
        return None


def _constant_string(node):
    if (hasattr(ast, "Constant") and isinstance(node, ast.Constant)
            and isinstance(node.value, string_types)):
        return node.value
    if isinstance(node, ast.Str):
        return node.s
    if (hasattr(ast, "Index") and isinstance(node, ast.Index)
            and hasattr(node, "value")):
        return _constant_string(node.value)
    return None


def _key_name(node, env=None):
    key = _constant_string(node)
    if key is not None:
        return key
    if env is not None and isinstance(node, ast.Name):
        value = env.get(node.id)
        if isinstance(value, string_types):
            return value
    return None


def _subscript_key(node, env=None):
    key = node.slice
    if (hasattr(ast, "Index") and isinstance(key, ast.Index)
            and hasattr(key, "value")):
        key = key.value
    return _key_name(key, env)


def _target_path(node):
    if isinstance(node, (ast.Name, ast.Attribute)):
        return tree.module_path_str(node)
    return None


class BadLogSensitiveKeyUseLinter(base.BaseLinter):
    """Detect sensitive dictionary keys that can reappear in log output.

    Sensitive keys and the calls which submit log records are project
    configuration. The rule follows only explicit copies, merges, branches,
    and aliases to the same dictionary object.
    """

    off_by_default = False

    _code = 'DUO139'
    _error_tmpl = (
        'DUO139 sensitive key may be reintroduced in log output'
    )

    config = None
    options = None
    sensitive_keys = ()
    log_calls = ()
    adapter_calls = ()

    _sensitive_aliases = (
        'sensitive_keys',
        'dlint_sensitive_keys',
        'sensitive_fields',
        'sensitive_field_names',
        'sensitive_key_names',
        'sensitive_names',
        'known_sensitive_keys',
        'sensitive_log_keys',
        'dlint_sensitive_log_keys',
        'log_sensitive_keys',
        'redacted_keys',
        'redact_keys',
    )
    _log_aliases = (
        'log_calls',
        'log_call',
        'actual_log_calls',
        'log_submit_calls',
        'dlint_log_calls',
        'logging_calls',
        'dlint_logging_calls',
        'log_sinks',
        'dlint_log_sinks',
        'sink_calls',
        'log_call_paths',
        'log_entry_points',
        'logging_sinks',
        'sink_functions',
        'sinks',
        'submit_calls',
        'emit_calls',
    )
    _adapter_aliases = (
        'adapter_calls',
        'adapter_call',
        'dlint_adapter_calls',
        'adapters',
        'log_adapters',
        'dlint_log_adapters',
    )
    _config_aliases = (
        'config',
        'log_config',
        'dlint_log_config',
        'dlint_config',
        'sensitive_log_config',
        'dlint_sensitive_log_config',
        'dlint_log_sensitive_config',
    )

    def __init__(self, *args, **kwargs):
        self._runtime_config = {}
        if args and isinstance(args[0], dict):
            self._runtime_config.update(args[0])
        elif args and isinstance(args[0], string_types):
            self._runtime_config['config'] = args[0]

        canonical = {
            'sensitive_keys': 'sensitive_keys',
            'sensitive_fields': 'sensitive_keys',
            'sensitive_field_names': 'sensitive_keys',
            'sensitive_key_names': 'sensitive_keys',
            'sensitive_log_keys': 'sensitive_keys',
            'log_sensitive_keys': 'sensitive_keys',
            'redacted_keys': 'sensitive_keys',
            'redact_keys': 'sensitive_keys',
            'log_calls': 'log_calls',
            'logging_calls': 'log_calls',
            'log_sinks': 'log_calls',
            'sink_calls': 'log_calls',
            'log_call_paths': 'log_calls',
            'sinks': 'log_calls',
            'adapter_calls': 'adapter_calls',
            'adapters': 'adapter_calls',
            'log_adapters': 'adapter_calls',
        }
        for key in (self._sensitive_aliases + self._log_aliases
                    + self._adapter_aliases):
            if key in kwargs:
                value = kwargs.pop(key)
                self._runtime_config[key] = value
                if key in canonical:
                    setattr(self, canonical[key], value)
        for key in self._config_aliases:
            if key in kwargs:
                self._runtime_config[key] = kwargs.pop(key)

        super(BadLogSensitiveKeyUseLinter, self).__init__()

    @classmethod
    def from_config(cls, config):
        linter = cls()
        if isinstance(config, string_types):
            linter._runtime_config['config'] = config
        elif isinstance(config, dict):
            linter._runtime_config.update(config)
        else:
            linter._runtime_config.update(vars(config))
        return linter

    @classmethod
    def from_file(cls, path):
        return cls.from_config('@' + path)

    def configure(self, config):
        if isinstance(config, dict):
            self._runtime_config.update(config)
        elif isinstance(config, string_types):
            self._runtime_config['config'] = config
        else:
            self._runtime_config.update(vars(config))
        return self

    def visit_Module(self, node):
        config = self._get_config()
        self._sensitive_keys = set(config['sensitive_keys'])
        self._sinks = dict(config['sinks'])
        self._adapter_calls = set(config['adapter_calls'])
        if not self._sensitive_keys:
            for keys in self._sinks.values():
                self._sensitive_keys.update(keys or ())

        if not self._sensitive_keys or not self._sinks:
            return

        _Analyzer(self, node).analyze()

    def _get_config(self):
        config = {
            'sensitive_keys': [],
            'log_calls': [],
            'adapter_calls': [],
            'sinks': {},
        }

        sources = [
            getattr(self, 'config', None),
            self._runtime_config,
            self._options_config(),
            self._environment_config(),
        ]
        for source in sources:
            if not source:
                continue
            normalized = self._normalize_config(source)
            for key in ('sensitive_keys', 'log_calls', 'adapter_calls'):
                config[key].extend(normalized[key])
            config['sinks'].update(normalized['sinks'])

        explicit = {}
        for key in (
                self._sensitive_aliases + self._log_aliases
                + self._adapter_aliases):
            value = getattr(self, key, None)
            if value:
                explicit[key] = value
        for key in ('SENSITIVE_KEYS', 'LOG_CALLS', 'ADAPTER_CALLS'):
            value = getattr(self, key, None)
            if value:
                explicit[key] = value
        normalized = self._normalize_config(explicit)
        for key in ('sensitive_keys', 'log_calls', 'adapter_calls'):
            config[key].extend(normalized[key])
        config['sinks'].update(normalized['sinks'])

        config['sensitive_keys'] = sorted(
            set(config['sensitive_keys'])
        )
        config['log_calls'] = sorted(set(config['log_calls']))
        config['adapter_calls'] = sorted(set(config['adapter_calls']))
        for path in config['log_calls']:
            config['sinks'].setdefault(_normalize_path(path), None)
        return config

    def _normalize_config(self, source):
        result = {
            'sensitive_keys': [],
            'log_calls': [],
            'adapter_calls': [],
            'sinks': {},
        }
        if not source:
            return result
        if isinstance(source, string_types):
            source = _load_config_blob(source)
            if source is None:
                return result
        if not isinstance(source, dict):
            try:
                source = vars(source)
            except TypeError:
                return result

        lowered = {}
        for key, value in source.items():
            name = str(key).lower().replace('-', '_').replace('.', '_')
            lowered[name] = value

        nested_aliases = ('dlint', 'duo139', 'sensitive_log_context',
                          'bad_log_sensitive_key_use')
        for alias in self._config_aliases + nested_aliases:
            if alias not in lowered:
                continue
            blobs = lowered[alias]
            if not isinstance(blobs, (list, tuple)):
                blobs = [blobs]
            for blob in blobs:
                if isinstance(blob, string_types):
                    blob = _load_config_blob(blob)
                if not isinstance(blob, dict):
                    continue
                nested = self._normalize_config(blob)
                for key in ('sensitive_keys', 'log_calls', 'adapter_calls'):
                    result[key].extend(nested[key])
                result['sinks'].update(nested['sinks'])

        for alias in self._sensitive_aliases:
            if alias in lowered:
                result['sensitive_keys'].extend(
                    _split_strings(lowered[alias])
                )

        for alias in self._log_aliases:
            if alias not in lowered:
                continue
            value = lowered[alias]
            if isinstance(value, dict):
                for path, keys in value.items():
                    path = _normalize_path(path)
                    result['log_calls'].append(path)
                    keys = _split_strings(keys)
                    result['sinks'][path] = set(keys) if keys else None
            else:
                result['log_calls'].extend(
                    _normalize_path(path)
                    for path in _split_strings(value)
                )

        for alias in self._adapter_aliases:
            if alias in lowered:
                result['adapter_calls'].extend(
                    _normalize_path(path)
                    for path in _split_strings(lowered[alias])
                )

        result['sensitive_keys'] = sorted(
            set(result['sensitive_keys'])
        )
        result['log_calls'] = sorted(set(result['log_calls']))
        result['adapter_calls'] = sorted(
            set(result['adapter_calls'])
        )
        return result

    def _options_config(self):
        options = getattr(self, 'options', None)
        if not options:
            try:
                from .. import extension
                options = extension.Flake8Extension.options
            except (ImportError, AttributeError):
                options = None
        return options or {}

    def _environment_config(self):
        config = {}
        blob = (os.environ.get('DLINT_LOG_CONFIG')
                or os.environ.get('DLINT_CONFIG'))
        if blob:
            loaded = _load_config_blob(blob)
            if isinstance(loaded, dict):
                config.update(loaded)
        if os.environ.get('DLINT_SENSITIVE_KEYS'):
            config['sensitive_keys'] = os.environ['DLINT_SENSITIVE_KEYS']
        if os.environ.get('DLINT_LOG_CALLS'):
            config['log_calls'] = os.environ['DLINT_LOG_CALLS']
        return config


class _Analyzer(object):
    def __init__(self, linter, module):
        self.linter = linter
        self.module = module
        self.namespace = linter.namespace
        self.sensitive_keys = linter._sensitive_keys
        self.sinks = linter._sinks
        self.adapter_calls = linter._adapter_calls
        self.functions = {}
        self.global_env = _Env()
        self.returns = []
        self.active_functions = set()
        self.seen_results = set()
        self._collect_functions(module)

    def analyze(self):
        self._exec_block(self.module.body, self.global_env)
        for definitions in list(self.functions.values()):
            for function in definitions:
                self._analyze_function(function, {}, set())

    def _collect_functions(self, node):
        body = getattr(node, 'body', ())
        for child in body:
            if isinstance(child, (ast.FunctionDef,
                                  getattr(ast, 'AsyncFunctionDef', ast.FunctionDef))):
                self.functions.setdefault(child.name, []).append(child)
                self._collect_nested(child)
            elif isinstance(child, ast.ClassDef):
                for inner in child.body:
                    if isinstance(inner, (ast.FunctionDef,
                                          getattr(ast, 'AsyncFunctionDef', ast.FunctionDef))):
                        self.functions.setdefault(inner.name, []).append(inner)
                        self.functions.setdefault(
                            '{}.{}'.format(child.name, inner.name), []
                        ).append(inner)
                        self._collect_nested(inner)

    def _collect_nested(self, function):
        for child in getattr(function, 'body', ()):
            if isinstance(child, (ast.FunctionDef,
                                  getattr(ast, 'AsyncFunctionDef', ast.FunctionDef))):
                self.functions.setdefault(child.name, []).append(child)
                self._collect_nested(child)

    def _exec_block(self, statements, env):
        for statement in statements:
            if env is None:
                break
            env = self._exec_statement(statement, env)
        return env

    def _exec_statement(self, statement, env):
        if isinstance(statement, (ast.FunctionDef,
                                  getattr(ast, 'AsyncFunctionDef', ast.FunctionDef),
                                  ast.ClassDef)):
            return env

        if isinstance(statement, ast.Assign):
            value = self._eval_expr(statement.value, env)
            for target in statement.targets:
                self._assign(target, value, env)
            return env

        if hasattr(ast, 'AnnAssign') and isinstance(statement, ast.AnnAssign):
            if statement.value is not None:
                self._assign(
                    statement.target,
                    self._eval_expr(statement.value, env),
                    env,
                )
            return env

        if isinstance(statement, ast.AugAssign):
            self._exec_augassign(statement, env)
            return env

        if isinstance(statement, ast.Expr):
            self._eval_expr(statement.value, env)
            return env

        if isinstance(statement, ast.Delete):
            for target in statement.targets:
                self._delete_target(target, env)
            return env

        if isinstance(statement, ast.If):
            return self._exec_if(statement, env)

        if isinstance(statement, (ast.For,
                                  getattr(ast, 'AsyncFor', ast.For))):
            return self._exec_loop(
                statement.body, env, statement.orelse
            )

        if isinstance(statement, ast.While):
            return self._exec_loop(statement.body, env, statement.orelse)

        if isinstance(statement, (ast.With,
                                  getattr(ast, 'AsyncWith', ast.With))):
            for item in statement.items:
                if item.optional_vars is not None:
                    self._assign(item.optional_vars, _UNKNOWN, env)
            return self._exec_block(statement.body, env)

        if isinstance(statement, ast.Try):
            return self._exec_try(statement, env)

        if hasattr(ast, 'TryStar') and isinstance(statement, ast.TryStar):
            return self._exec_try(statement, env)

        if hasattr(ast, 'Match') and isinstance(statement, ast.Match):
            return self._exec_match(statement, env)

        if isinstance(statement, ast.Return):
            if statement.value is None:
                self.returns.append(_UNKNOWN)
            else:
                self.returns.append(self._eval_expr(statement.value, env))
            return None

        if isinstance(statement, ast.Raise):
            if statement.exc is not None:
                self._eval_expr(statement.exc, env)
            return None

        if isinstance(statement, (ast.Break, ast.Continue, ast.Pass)):
            return env

        if isinstance(statement, ast.Import):
            for alias in statement.names:
                env.set(alias.asname or alias.name.split('.')[0], _UNKNOWN)
            return env

        if isinstance(statement, ast.ImportFrom):
            for alias in statement.names:
                if alias.name != '*':
                    env.set(alias.asname or alias.name, _UNKNOWN)
            return env

        return env

    def _exec_if(self, statement, env):
        base = env
        true_env = self._exec_block(statement.body, base.clone())
        false_env = self._exec_block(statement.orelse, base.clone())
        return self._merge_envs(base, [true_env, false_env])

    def _exec_loop(self, body, env, orelse):
        base = env
        body_env = self._exec_block(body, base.clone())
        merged = self._merge_envs(base, [body_env])
        if orelse:
            merged = self._exec_block(orelse, merged)
        return merged

    def _exec_try(self, statement, env):
        base = env
        branches = []

        body_env = self._exec_block(statement.body, base.clone())
        if body_env is not None and statement.orelse:
            body_env = self._exec_block(statement.orelse, body_env)
        branches.append(body_env)

        for handler in statement.handlers:
            handler_env = self._exec_block(handler.body, base.clone())
            branches.append(handler_env)

        if not any(handler.type is None for handler in statement.handlers):
            branches.append(base.clone())

        merged = self._merge_envs(base, branches)
        if merged is not None and statement.finalbody:
            merged = self._exec_block(statement.finalbody, merged)
        return merged

    def _exec_match(self, statement, env):
        branches = [env.clone()]
        for case in statement.cases:
            branches.append(self._exec_block(case.body, env.clone()))
        return self._merge_envs(env, branches)

    def _merge_envs(self, base, branches):
        active = [branch for branch in branches if branch is not None]
        if not active:
            return None
        if len(active) == 1:
            return active[0]

        names = set(base.values)
        for branch in active:
            names.update(branch.values)

        values = {}
        writes = set()
        for name in names:
            candidates = []
            for branch in active:
                if name in branch.values:
                    candidates.append(branch.values[name])
                if name in branch.writes:
                    writes.add(name)
            if name in base.values and any(
                    name not in branch.writes for branch in active):
                candidates.append(base.values[name])
            if candidates:
                values[name] = _union(candidates)
        return _Env(values, writes)

    def _exec_augassign(self, statement, env):
        target = statement.target
        if isinstance(target, ast.Name) and isinstance(statement.op, ast.BitOr):
            current = env.get(target.id)
            source = self._eval_expr(statement.value, env)
            self._merge_into(current, source, statement)
            env.mark_aliases(current)
            return

        if isinstance(target, ast.Subscript):
            key = _subscript_key(target, env)
            value = env.get(_target_path(target.value))
            if key is not None:
                for obj in _iter_dicts(value):
                    obj.add(key, statement, refresh=True)
            env.mark_aliases(value)
            return

        path = _target_path(target)
        if path is not None:
            env.set(path, _UNKNOWN)

    def _assign(self, target, value, env):
        if isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._assign(item, _UNKNOWN, env)
            return
        if isinstance(target, ast.Subscript):
            key = _subscript_key(target, env)
            container = self._eval_expr(target.value, env)
            if key is not None:
                for obj in _iter_dicts(container):
                    obj.add(key, target, refresh=True)
            env.mark_aliases(container)
            return
        path = _target_path(target)
        if path is not None:
            env.set(path, value)

    def _delete_target(self, target, env):
        if isinstance(target, ast.Subscript):
            key = _subscript_key(target, env)
            container = self._eval_expr(target.value, env)
            if key is not None:
                for obj in _iter_dicts(container):
                    obj.remove(key, self.sensitive_keys)
            env.mark_aliases(container)
        elif isinstance(target, (ast.Name, ast.Attribute)):
            path = _target_path(target)
            if path in env.values:
                del env.values[path]
                env.writes.add(path)

    def _eval_expr(self, node, env):
        if isinstance(node, ast.Name):
            return env.get(node.id)
        if (hasattr(ast, "Constant") and isinstance(node, ast.Constant)
                and isinstance(node.value, string_types)):
            return node.value
        if isinstance(node, ast.Str):
            return node.s
        if isinstance(node, ast.Attribute):
            return env.get(tree.module_path_str(node))
        if isinstance(node, ast.Dict):
            return self._eval_dict(node, env)
        if hasattr(ast, 'DictComp') and isinstance(node, ast.DictComp):
            return _UNKNOWN
        if isinstance(node, ast.IfExp):
            return _union([
                self._eval_expr(node.body, env.clone()),
                self._eval_expr(node.orelse, env.clone()),
            ])
        if (isinstance(node, ast.BinOp)
                and isinstance(node.op, ast.BitOr)):
            left = self._copy_value(
                self._eval_expr(node.left, env),
                keep_removed=True,
                node=node,
            )
            right = self._eval_expr(node.right, env)
            self._merge_into(left, right, node)
            return left
        if isinstance(node, ast.Call):
            return self._eval_call(node, env)
        if hasattr(ast, 'NamedExpr') and isinstance(node, ast.NamedExpr):
            value = self._eval_expr(node.value, env)
            self._assign(node.target, value, env)
            return value
        if isinstance(node, (ast.Tuple, ast.List)):
            return _union(
                self._eval_expr(item, env) for item in node.elts
            )
        return _UNKNOWN

    def _eval_dict(self, node, env):
        result = _DictValue()
        for key_node, value_node in zip(node.keys, node.values):
            self._eval_expr(value_node, env)
            if key_node is None:
                source = self._eval_expr(value_node, env)
                self._merge_into(result, source, node)
                continue
            key = _key_name(key_node, env)
            if key is not None:
                result.add(key, node, initial=True)
        return result

    def _eval_dict_comp(self, node, env):
        if len(node.generators) != 1:
            return _UNKNOWN
        generator = node.generators[0]
        source = _UNKNOWN
        iterable = generator.iter
        if (isinstance(iterable, ast.Call)
                and isinstance(iterable.func, ast.Attribute)
                and iterable.func.attr in ('items', 'keys')):
            source = self._eval_expr(iterable.func.value, env)
        if not list(_iter_dicts(source)):
            return _UNKNOWN

        result = self._copy_value(source, node=node)
        target_name = None
        if isinstance(generator.target, (ast.Tuple, ast.List)):
            if generator.target.elts:
                target_name = _target_path(generator.target.elts[0])
        else:
            target_name = _target_path(generator.target)

        removed = None
        allowed = None
        for condition in generator.ifs:
            if not isinstance(condition, ast.Compare):
                continue
            if len(condition.ops) != 1 or len(condition.comparators) != 1:
                continue
            left = condition.left
            if not isinstance(left, ast.Name) or left.id != target_name:
                continue
            keys = self._literal_string_values(
                condition.comparators[0], env
            )
            if keys is None:
                continue
            operation = condition.ops[0]
            if isinstance(operation, (ast.NotEq, ast.NotIn)):
                removed = (removed or set()) | set(keys)
            elif isinstance(operation, (ast.Eq, ast.In)):
                allowed = (allowed or set()) | set(keys)

        for obj in _iter_dicts(result):
            if removed:
                for key in removed:
                    obj.keys.discard(key)
                    obj.removed.discard(key)
                    obj.last_add.pop(key, None)
                    obj.origins.pop(key, None)
            if allowed is not None:
                obj.keys.intersection_update(allowed)
                obj.removed.intersection_update(allowed)
                obj.last_add = {
                    key: value for key, value in obj.last_add.items()
                    if key in allowed
                }
                obj.origins = {
                    key: value for key, value in obj.origins.items()
                    if key in allowed
                }
        return result

    def _literal_string_values(self, node, env):
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            values = []
            for item in node.elts:
                key = _key_name(item, env)
                if key is None:
                    return None
                values.append(key)
            return values
        key = _key_name(node, env)
        if key is not None:
            return [key]
        return None

    def _eval_call(self, node, env):
        path = tree.module_path_str(node.func)
        if isinstance(node.func, ast.Attribute):
            receiver = self._eval_expr(node.func.value, env)
            result = self._eval_method_call(
                receiver, node.func.attr, node, env
            )
            if result is not _UNKNOWN:
                return result

        if (path in ('dict', 'builtins.dict')
                or self._matches_path(node.func, 'builtins.dict')):
            return self._eval_dict_call(node, env)
        if (self._matches_path(node.func, 'copy.copy')
                or self._matches_path(node.func, 'copy.deepcopy')):
            if node.args:
                return self._copy_value(
                    self._eval_expr(node.args[0], env), node=node
                )
            return _UNKNOWN
        if (path in ('dict.fromkeys', 'builtins.dict.fromkeys')
                or self._matches_path(node.func, 'builtins.dict.fromkeys')):
            return self._eval_fromkeys(node, env)
        if (self._matches_path(node.func, 'collections.ChainMap')
                or self._matches_path(node.func, 'chainmap.ChainMap')):
            result = _DictValue()
            for arg in node.args:
                self._merge_into(
                    result, self._eval_expr(arg, env), node
                )
            return result

        functions = self._resolve_functions(node)
        if functions:
            values = []
            for function in functions:
                values.append(self._call_function(function, node, env))
            return _union(values)

        sink = self._matching_sink(node)
        if sink is not None:
            self._handle_sink(node, env, sink)
            return _UNKNOWN

        return _UNKNOWN

    def _eval_method_call(self, receiver, method, node, env):
        if method == 'copy':
            return self._copy_value(receiver, node=node)
        if method == 'update':
            args = [self._eval_expr(arg, env) for arg in node.args]
            keywords = self._keyword_values(node, env)
            for value in args + keywords:
                self._merge_into(receiver, value, node)
            env.mark_aliases(receiver)
            return _UNKNOWN
        if method == 'pop':
            key = None
            if node.args:
                key = _key_name(node.args[0], env)
            for obj in _iter_dicts(receiver):
                if key is None:
                    obj.unknown_keys = True
                    for sensitive in self.sensitive_keys:
                        obj.remove(sensitive, self.sensitive_keys)
                else:
                    obj.remove(key, self.sensitive_keys)
            env.mark_aliases(receiver)
            return _UNKNOWN
        if method == 'clear':
            for obj in _iter_dicts(receiver):
                sensitive = set(obj.keys) | set(obj.removed)
                if obj.unknown_keys:
                    sensitive |= self.sensitive_keys
                for key in sensitive:
                    obj.remove(key, self.sensitive_keys)
            env.mark_aliases(receiver)
            return _UNKNOWN
        if method == 'setdefault':
            key = None
            if node.args:
                key = _key_name(node.args[0], env)
            if key is not None:
                for obj in _iter_dicts(receiver):
                    obj.add(key, node, refresh=True)
            env.mark_aliases(receiver)
            return _UNKNOWN
        return _UNKNOWN

    def _eval_dict_call(self, node, env):
        result = _DictValue()
        if len(node.args) == 1 and not node.keywords:
            source = self._eval_expr(node.args[0], env)
            return self._copy_value(source, node=node)

        for arg in node.args:
            source = self._eval_expr(arg, env)
            self._merge_into(result, source, node)
        for keyword in node.keywords:
            if keyword.arg is None:
                self._merge_into(
                    result, self._eval_expr(keyword.value, env), node
                )
            else:
                result.add(keyword.arg, node, initial=True)
        return result

    def _eval_fromkeys(self, node, env):
        result = _DictValue()
        if node.args:
            keys = self._literal_keys(node.args[0], env)
            if keys is None:
                result.unknown_keys = True
            else:
                for key in keys:
                    result.add(key, node, initial=True)
        return result

    def _literal_keys(self, node, env):
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            keys = []
            for item in node.elts:
                key = _key_name(item, env)
                if key is None:
                    return None
                keys.append(key)
            return keys
        value = self._eval_expr(node, env)
        keys = set()
        for obj in _iter_dicts(value):
            keys.update(obj.keys)
        return sorted(keys)

    def _copy_value(self, value, keep_removed=False, node=None):
        values = []
        for item in (value.values if isinstance(value, _Union) else (value,)):
            if isinstance(item, _DictValue):
                copy = _DictValue(item.keys, item.unknown_keys)
                if keep_removed:
                    copy.removed = set(item.removed)
                if node is not None:
                    for key in copy.keys:
                        copy.last_add[key] = node
                        copy.origins[key] = node
                values.append(copy)
            else:
                copy = _DictValue(unknown_keys=True)
                values.append(copy)
        return _union(values)

    def _merge_into(self, target, source, node):
        targets = list(_iter_dicts(target))
        sources = list(_iter_dicts(source))

        for obj in targets:
            if not sources:
                for key in list(obj.removed):
                    obj.add(key, node, refresh=True)
                continue
            for source_obj in sources:
                for key in source_obj.keys:
                    obj.add(key, node, refresh=True)
                if source_obj.unknown_keys:
                    for key in list(obj.removed):
                        obj.add(key, node, refresh=True)

    def _keyword_values(self, node, env):
        values = []
        for keyword in node.keywords:
            value = self._eval_expr(keyword.value, env)
            if keyword.arg is None:
                values.append(value)
            else:
                obj = _DictValue([keyword.arg])
                value = _union([obj])
                values.append(value)
        return values

    def _handle_sink(self, node, env, sink):
        values = []
        for arg in node.args:
            values.append(self._eval_expr(arg, env))
        for keyword in node.keywords:
            values.append(self._eval_expr(keyword.value, env))

        configured = self.sinks.get(sink)
        sensitive_keys = configured or self.sensitive_keys
        events = []

        for value in values:
            for obj in _iter_dicts(value):
                for key in sensitive_keys:
                    if key in obj.keys:
                        event = (obj.origins.get(key)
                                 or obj.last_add.get(key))
                        events.append(event if event is not None else node)
                    elif key in obj.removed:
                        events.append(node)

        if events:
            event = max(events, key=lambda item: (
                getattr(item, 'lineno', 0),
                getattr(item, 'col_offset', 0),
            ))
            self._add_result(event)

    def _call_function(self, function, call, env):
        if id(function) in self.active_functions:
            return _UNKNOWN

        self.active_functions.add(id(function))
        saved_returns = self.returns
        self.returns = []
        try:
            local = _Env(dict(env.values))
            self._bind_arguments(function, call, local, env)
            self._exec_block(function.body, local)
            result = _union(self.returns) if self.returns else _UNKNOWN
        finally:
            self.returns = saved_returns
            self.active_functions.remove(id(function))
        return result

    def _analyze_function(self, function, bindings, active):
        if id(function) in self.active_functions:
            return
        self.active_functions.add(id(function))
        saved_returns = self.returns
        self.returns = []
        try:
            local = _Env(dict(self.global_env.values))
            for name in self._argument_names(function):
                local.set(name, _UNKNOWN)
            args = list(getattr(function.args, 'args', ()))
            defaults = list(getattr(function.args, 'defaults', ()))
            if defaults:
                offset = len(args) - len(defaults)
                for index, default in enumerate(defaults):
                    local.set(
                        args[offset + index].arg,
                        self._eval_expr(default, local),
                    )
            kwonlyargs = list(getattr(function.args, 'kwonlyargs', ()))
            kw_defaults = list(getattr(function.args, 'kw_defaults', ()))
            for arg, default in zip(kwonlyargs, kw_defaults):
                if default is not None:
                    local.set(arg.arg, self._eval_expr(default, local))
            for name, value in bindings.items():
                local.set(name, value)
            self._exec_block(function.body, local)
        finally:
            self.returns = saved_returns
            self.active_functions.remove(id(function))

    def _bind_arguments(self, function, call, local, caller_env):
        args = getattr(function.args, 'args', ())
        defaults = getattr(function.args, 'defaults', ())
        default_values = {}
        if defaults:
            offset = len(args) - len(defaults)
            for index, default in enumerate(defaults):
                default_values[offset + index] = self._eval_expr(
                    default, caller_env
                )

        for index, arg in enumerate(args):
            if index < len(call.args):
                value = self._eval_expr(call.args[index], caller_env)
            else:
                value = default_values.get(index, _UNKNOWN)
            local.set(arg.arg, value)

        keywords = {}
        for keyword in call.keywords:
            if keyword.arg is not None:
                keywords[keyword.arg] = self._eval_expr(
                    keyword.value, caller_env
                )
                local.set(keyword.arg, keywords[keyword.arg])
                continue

            expanded = self._eval_expr(keyword.value, caller_env)
            for obj in _iter_dicts(expanded):
                kwargs_object = _DictValue(
                    obj.keys, obj.unknown_keys
                )
                kwargs_object.removed = set(obj.removed)
                kwarg_name = getattr(function.args, 'kwarg', None)
                if kwarg_name:
                    local.set(kwarg_name, kwargs_object)
                for key in obj.keys:
                    local.set(key, _UNKNOWN)

        kwarg_name = getattr(function.args, 'kwarg', None)
        if kwarg_name and (kwarg_name not in local.values
                           or local.get(kwarg_name) is _UNKNOWN):
            kwargs_object = _DictValue()
            for name in keywords:
                kwargs_object.add(name, initial=True)
            local.set(kwarg_name, kwargs_object)

    def _argument_names(self, function):
        names = []
        for arg in getattr(function.args, 'args', ()):
            names.append(arg.arg)
        for arg in getattr(function.args, 'kwonlyargs', ()):
            names.append(arg.arg)
        for attr in ('vararg', 'kwarg'):
            arg = getattr(function.args, attr, None)
            if arg is not None:
                names.append(arg.arg)
        return names

    def _resolve_functions(self, call):
        path = tree.module_path_str(call.func)
        if not path:
            return ()
        if path in self.functions:
            return tuple(self.functions[path])
        if '.' in path:
            first = path.split('.', 1)[0]
            last = path.rsplit('.', 1)[-1]
            if first in ('self', 'cls'):
                return tuple(self.functions.get(last, ()))
        return ()

    def _matching_sink(self, call):
        for configured in self.sinks:
            if self._matches_path(call.func, configured):
                return configured
        return None

    def _matches_path(self, node, configured):
        path = tree.module_path_str(node)
        configured = _normalize_path(configured)
        if not path:
            return False
        if path == configured:
            return True
        try:
            if self.namespace.illegal_module_imported(path, configured):
                return True
        except (AttributeError, TypeError):
            pass

        path_parts = path.split('.')
        configured_parts = configured.split('.')
        if (len(configured_parts) > 1
                and path_parts[-len(configured_parts):] == configured_parts):
            return True
        if (len(path_parts) > 1
                and configured_parts[-len(path_parts):] == path_parts):
            return True
        return False

    def _add_result(self, node):
        marker = (node.lineno, node.col_offset)
        if marker in self.seen_results:
            return
        self.seen_results.add(marker)
        self.linter.results.append(
            base.Flake8Result(
                lineno=node.lineno,
                col_offset=node.col_offset,
                message=self.linter._error_tmpl,
            )
        )


# Descriptive aliases for integrations which refer to rules by class name.
SensitiveLogKeyLinter = BadLogSensitiveKeyUseLinter
SensitiveKeyLoggingLinter = BadLogSensitiveKeyUseLinter
LogSensitiveKeyLinter = BadLogSensitiveKeyUseLinter
LogSensitiveKeysLinter = BadLogSensitiveKeyUseLinter
BadSensitiveLogKeyUseLinter = BadLogSensitiveKeyUseLinter
BadSensitiveKeyLoggingLinter = BadLogSensitiveKeyUseLinter
BadLoggingSensitiveKeyUseLinter = BadLogSensitiveKeyUseLinter
BadSensitiveDataLoggingLinter = BadLogSensitiveKeyUseLinter
BadLogSensitiveDataUseLinter = BadLogSensitiveKeyUseLinter
BadLogSensitiveDataLinter = BadLogSensitiveKeyUseLinter
BadSensitiveLogKeyUseLinter = BadLogSensitiveKeyUseLinter
BadSensitiveLogKeyLinter = BadLogSensitiveKeyUseLinter
BadSensitiveKeyLogLinter = BadLogSensitiveKeyUseLinter
SensitiveLogContextLinter = BadLogSensitiveKeyUseLinter
BadSensitiveLogContextLinter = BadLogSensitiveKeyUseLinter
SensitiveLogContextUseLinter = BadLogSensitiveKeyUseLinter
BadSensitiveKeysLoggingLinter = BadLogSensitiveKeyUseLinter
SensitiveLogDataLinter = BadLogSensitiveKeyUseLinter
LogRedactionLinter = BadLogSensitiveKeyUseLinter
BadLogRedactionLinter = BadLogSensitiveKeyUseLinter
SensitiveKeyLogLinter = BadLogSensitiveKeyUseLinter
SensitiveDataLoggingLinter = BadLogSensitiveKeyUseLinter
