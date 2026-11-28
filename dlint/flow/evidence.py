#!/usr/bin/env python

"""Branch-sensitive evidence for temporary resource safety checks.

The analyzer in this module is deliberately small and dependency-free.  It
works on one parsed function at a time and only recognises source-level
contracts supplied by the caller (or declared in the same AST).  Nothing in
the analyzed source is imported, evaluated, or called.

An exit is classified as one of:

* ``normal`` - a normal return (or fall-through) after the configured check
  completed on that path.
* ``exception_cleanup`` - an exception exit whose resource was released by a
  recognised ``except``/``finally`` cleanup.
* ``contract_unknown`` - the resource was handed to a call whose contract is
  not known, so the analyzer cannot prove completion or a leak.
* ``unchecked`` / ``unchecked_exception`` - a normal/exception exit that
  reaches a return before the configured check completed.
"""

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast
import collections
import textwrap


_AST_CONSTANT = getattr(ast, 'Constant', ())
_AST_ASYNC_FOR = getattr(ast, 'AsyncFor', ())
_AST_ASYNC_WITH = getattr(ast, 'AsyncWith', ())
_AST_ASYNC_FUNCTION_DEF = getattr(ast, 'AsyncFunctionDef', ())
_AST_NAMED_EXPR = getattr(ast, 'NamedExpr', ())
_AST_AWAIT = getattr(ast, 'Await', ())
_AST_TRY_STAR = getattr(ast, 'TryStar', ())
_AST_MATCH = getattr(ast, 'Match', ())
_FUNCTION_DEF_TYPES = (ast.FunctionDef, _AST_ASYNC_FUNCTION_DEF)
_LOOP_TYPES = (ast.For, _AST_ASYNC_FOR, ast.While)
_WITH_TYPES = (ast.With, _AST_ASYNC_WITH)
_TRY_TYPES = (ast.Try, _AST_TRY_STAR)


NORMAL = 'normal'
EXCEPTION_CLEANUP = 'exception_cleanup'
CONTRACT_UNKNOWN = 'contract_unknown'
UNCHECKED = 'unchecked'
UNCHECKED_EXCEPTION = 'unchecked_exception'

NORMAL_RETURN = NORMAL
RECOGNIZED_EXCEPTION_CLEANUP = EXCEPTION_CLEANUP
UNKNOWN_CONTRACT = CONTRACT_UNKNOWN
UNCHECKED_RETURN = UNCHECKED


class ExitKind(object):
    """Compatibility names for the branch classifications."""

    NORMAL = NORMAL
    EXCEPTION_CLEANUP = EXCEPTION_CLEANUP
    CONTRACT_UNKNOWN = CONTRACT_UNKNOWN
    UNCHECKED = UNCHECKED
    UNCHECKED_EXCEPTION = UNCHECKED_EXCEPTION


Status = ExitKind


DEFAULT_FACTORIES = (
    'acquire',
    'acquire_temp',
    'acquire_temporary',
    'acquire_resource',
    'acquire_temp_resource',
    'create_temp',
    'create_temporary',
    'create_temp_resource',
    'open_temp',
    'open_temporary',
    'temp_resource',
    'temporary_resource',
    'mkstemp',
    'mkdtemp',
    'mktemp',
    'tempnam',
    'tmpnam',
    'NamedTemporaryFile',
    'TemporaryFile',
    'TemporaryDirectory',
    'SpooledTemporaryFile',
    'tempfile.mkstemp',
    'tempfile.mkdtemp',
    'tempfile.mktemp',
    'tempfile.NamedTemporaryFile',
    'tempfile.TemporaryFile',
    'tempfile.TemporaryDirectory',
    'tempfile.SpooledTemporaryFile',
    'os.tempnam',
    'os.tmpnam',
)

DEFAULT_CHECKS = (
    'security_check',
    'check_security',
    'safety_check',
    'check_safety',
    'check',
    'validate',
    'verify',
    'authorize',
    'sanitize',
    'cleanup',
    'clean_up',
    'release',
    'revoke',
    'close',
    'finish',
    'finalize',
    'dispose',
    'teardown',
    'deregister',
    'invalidate',
    'unlink',
    'remove',
    'delete',
    'discard',
)

DEFAULT_HANDOFFS = (
    'handoff',
    'hand_off',
    'transfer',
    'transfer_ownership',
    'give',
    'yield_to',
    'send_to',
)


CONTRACT_RAISES = 'raises'
CONTRACT_BOOL = 'bool'
CONTRACT_RETURNS = 'returns'


_DECLARATION_MARKERS = (
    'check',
    'cleanup',
    'clean_up',
    'release',
    'guard',
    'safety',
    'contract',
    'convention',
    'declaration',
    'placeholder',
    'stub',
)


_FACTORY_DECLARATION_MARKERS = (
    'factory',
    'factories',
    'acquire',
    'resource',
    'temporary',
)


_HANDOFF_DECLARATION_MARKERS = (
    'handoff',
    'hand_off',
    'transfer',
    'ownership',
)


PathStep = collections.namedtuple(
    'PathStep',
    ['kind', 'lineno', 'col_offset', 'detail']
)


Finding = collections.namedtuple(
    'Finding',
    ['lineno', 'col_offset', 'message', 'status', 'kind', 'resource', 'evidence']
)


class ExitEvidence(object):
    """One reachable function exit and the check evidence for that path."""

    __slots__ = (
        'kind',
        'status',
        'lineno',
        'col_offset',
        'resource',
        'resource_name',
        'resources',
        'reason',
        'evidence',
        'cleanup',
        'factory',
    )

    def __init__(
        self,
        kind,
        status,
        lineno,
        col_offset,
        resource=None,
        resource_name=None,
        resources=None,
        reason='',
        evidence=None,
        cleanup=None,
        factory=None,
    ):
        self.kind = kind
        self.status = status
        self.lineno = lineno
        self.col_offset = col_offset
        self.resource = resource
        self.resource_name = resource_name
        self.resources = tuple(resources or ())
        self.reason = reason
        self.evidence = tuple(evidence or ())
        self.cleanup = cleanup
        self.factory = factory

    @property
    def is_problem(self):
        return self.status in (
            UNCHECKED,
            UNCHECKED_EXCEPTION,
            CONTRACT_UNKNOWN,
        )

    @property
    def exit_kind(self):
        return self.kind

    @property
    def classification(self):
        return self.status

    @property
    def is_normal(self):
        return self.status == NORMAL

    @property
    def is_recognized_exception_cleanup(self):
        return self.status == EXCEPTION_CLEANUP

    @property
    def is_contract_unknown(self):
        return self.status == CONTRACT_UNKNOWN

    @property
    def is_unchecked(self):
        return self.status in (UNCHECKED, UNCHECKED_EXCEPTION)

    @property
    def is_exception_path(self):
        return self.cleanup in ('except', 'finally') or self.kind == 'raise'

    @property
    def is_handoff(self):
        return self.cleanup == 'handoff'

    @property
    def cleanup_kind(self):
        return self.cleanup

    @property
    def evidence_text(self):
        return self.path_text

    @property
    def evidence_steps(self):
        return list(self.evidence)

    @property
    def path(self):
        return list(self.evidence)

    @property
    def resource_uid(self):
        return self.resource

    @property
    def divergence_lineno(self):
        return self.lineno

    @property
    def fork_lineno(self):
        return self.lineno

    @property
    def path_text(self):
        parts = []
        for step in self.evidence:
            if step.detail:
                parts.append('{}@{}:{}'.format(
                    step.kind, step.lineno, step.detail))
            else:
                parts.append('{}@{}'.format(step.kind, step.lineno))
        return ' -> '.join(parts)

    def to_dict(self):
        return {
            'kind': self.kind,
            'status': self.status,
            'lineno': self.lineno,
            'col_offset': self.col_offset,
            'resource': self.resource,
            'resource_name': self.resource_name,
            'resources': list(self.resources),
            'reason': self.reason,
            'cleanup': self.cleanup,
            'factory': self.factory,
            'evidence': [step._asdict() for step in self.evidence],
            'path_text': self.path_text,
        }


class FunctionEvidence(object):
    """Evidence for all exits of one local function."""

    __slots__ = ('name', 'lineno', 'col_offset', 'exits', 'resources', 'budget_exceeded')

    def __init__(self, name, lineno, col_offset, exits, resources, budget_exceeded=False):
        self.name = name
        self.lineno = lineno
        self.col_offset = col_offset
        self.exits = tuple(exits)
        self.resources = tuple(resources)
        self.budget_exceeded = budget_exceeded

    @property
    def problems(self):
        return tuple(exit for exit in self.exits if exit.is_problem)

    @property
    def normal_returns(self):
        return tuple(
            exit for exit in self.exits
            if exit.kind in ('return', 'fall') and exit.status == NORMAL
        )

    @property
    def exception_cleanups(self):
        return tuple(
            exit for exit in self.exits
            if exit.status == EXCEPTION_CLEANUP
        )

    @property
    def unknown_branches(self):
        return tuple(
            exit for exit in self.exits
            if exit.status == CONTRACT_UNKNOWN
        )

    @property
    def normal_exits(self):
        return self.normal_returns

    @property
    def exception_cleanup_exits(self):
        return self.exception_cleanups

    @property
    def contract_unknown_exits(self):
        return self.unknown_branches

    @property
    def unchecked_exits(self):
        return tuple(
            exit for exit in self.exits
            if exit.status in (UNCHECKED, UNCHECKED_EXCEPTION)
        )

    @property
    def all_exits(self):
        return self.exits

    def to_dict(self):
        return {
            'name': self.name,
            'lineno': self.lineno,
            'col_offset': self.col_offset,
            'budget_exceeded': self.budget_exceeded,
            'resources': [resource.to_dict() for resource in self.resources],
            'exits': [exit.to_dict() for exit in self.exits],
            'problems': [exit.to_dict() for exit in self.problems],
            'normal_returns': [exit.to_dict() for exit in self.normal_returns],
            'exception_cleanups': [exit.to_dict() for exit in self.exception_cleanups],
            'unknown_branches': [exit.to_dict() for exit in self.unknown_branches],
        }


class AnalysisConfig(object):
    """Configuration for the source-only resource check analysis.

    All API names are strings.  Qualified names and the final component of a
    qualified name are both accepted, so ``tempfile.mkstemp`` also matches an
    imported ``mkstemp`` call.  ``contracts`` maps check names to ``raises``
    (the call itself completes the check), ``bool`` (only a truthy branch is
    proof) or ``returns`` (a returned result is proof).
    """

    def __init__(
        self,
        factories=None,
        checks=None,
        handoffs=None,
        contracts=None,
        placeholders=None,
        conventions=None,
        track_parameters=True,
        report_unknown=True,
        max_paths=64,
        max_loop_iterations=2,
        **kwargs
    ):
        aliases = {
            'factory_functions': 'factories',
            'resource_factories': 'factories',
            'acquisition_apis': 'factories',
            'acquire_apis': 'factories',
            'check_functions': 'checks',
            'check_apis': 'checks',
            'security_checks': 'checks',
            'cleanup_functions': 'checks',
            'cleanup_apis': 'checks',
            'release_functions': 'checks',
            'release_apis': 'checks',
            'guard_functions': 'checks',
            'handoff_functions': 'handoffs',
            'transfer_apis': 'handoffs',
            'check_contracts': 'contracts',
            'placeholder_functions': 'placeholders',
            'stubs': 'placeholders',
            'declarations': 'conventions',
        }
        supplied = {
            'factories': factories,
            'checks': checks,
            'handoffs': handoffs,
            'contracts': contracts,
            'placeholders': placeholders,
            'conventions': conventions,
        }
        for key, value in kwargs.items():
            canonical = aliases.get(key, key)
            if canonical in supplied and value is not None:
                supplied[canonical] = value
        factories = supplied['factories']
        checks = supplied['checks']
        handoffs = supplied['handoffs']
        contracts = supplied['contracts']
        placeholders = supplied['placeholders']
        conventions = supplied['conventions']
        self.factories = _names(factories, DEFAULT_FACTORIES)
        self.checks = _names(checks, DEFAULT_CHECKS)
        self.handoffs = _names(handoffs, DEFAULT_HANDOFFS)
        self.contracts = _contracts(contracts)
        self.placeholders = _names(placeholders, ())
        self.conventions = tuple(conventions or ())
        self.track_parameters = bool(track_parameters)
        self.report_unknown = bool(report_unknown)
        self.max_paths = int(max_paths)
        self.max_loop_iterations = int(max_loop_iterations)
        if isinstance(placeholders, dict):
            _apply_role_mapping(placeholders, self)
        if isinstance(conventions, dict):
            _apply_role_mapping(conventions, self)

    def contract_for(self, name):
        for candidate in _match_candidates(name):
            if candidate in self.contracts:
                return self.contracts[candidate]
        return CONTRACT_RAISES


def _as_text_list(value):
    if value is None:
        return ()
    if isinstance(value, str):
        values = value.split(',')
    else:
        try:
            values = list(value)
        except TypeError:
            values = [value]

    result = []
    for item in values:
        if isinstance(item, str):
            result.extend(part.strip() for part in item.split(','))
        elif isinstance(item, (tuple, list, set)):
            result.extend(_as_text_list(item))
        elif item is not None:
            result.append(str(item))
    return tuple(item for item in result if item)


def _names(value, default):
    if value is None:
        return tuple(default)
    return _as_text_list(value)


def _contracts(value):
    result = {}
    if not value:
        return result
    if isinstance(value, dict):
        for key, contract in value.items():
            for name in _as_text_list(key):
                result[name] = _contract_value(contract)
        return result
    if isinstance(value, str):
        return result
    for item in value:
        if isinstance(item, dict):
            for key, contract in item.items():
                for name in _as_text_list(key):
                    result[name] = _contract_value(contract)
        elif isinstance(item, (tuple, list)) and len(item) == 2:
            for name in _as_text_list(item[0]):
                result[name] = _contract_value(item[1])
    return result


def _contract_value(value):
    if value is True:
        return CONTRACT_BOOL
    if value in (False, None):
        return CONTRACT_RAISES
    text = str(value).strip().lower()
    if text in ('bool', 'boolean', 'branch', 'predicate', 'check'):
        return CONTRACT_BOOL
    if text in ('return', 'returns', 'result', 'value'):
        return CONTRACT_RETURNS
    return CONTRACT_RAISES


def _apply_role_mapping(mapping, config):
    if not isinstance(mapping, dict):
        return
    for name, role in mapping.items():
        name = str(name)
        text = str(role).strip().lower()
        if text in ('factory', 'factories', 'acquire', 'acquisition'):
            config.factories = tuple(dict.fromkeys(config.factories + (name,)))
        elif text in ('handoff', 'transfer', 'ownership', 'hand_off'):
            config.handoffs = tuple(dict.fromkeys(config.handoffs + (name,)))
        elif text in ('check', 'cleanup', 'release', 'guard', 'validator', 'safety'):
            config.checks = tuple(dict.fromkeys(config.checks + (name,)))
        elif text in ('raises', 'bool', 'boolean', 'returns', 'result'):
            config.checks = tuple(dict.fromkeys(config.checks + (name,)))
            config.contracts[name] = _contract_value(text)


def _match_candidates(name):
    if not name:
        return ()
    parts = name.split('.')
    result = [name, parts[-1]]
    for index in range(1, len(parts)):
        result.append('.'.join(parts[index:]))
    return tuple(result)


class _Resource(object):
    __slots__ = ('uid', 'name', 'lineno', 'col_offset', 'factory')

    def __init__(self, uid, name, lineno, col_offset, factory):
        self.uid = uid
        self.name = name
        self.lineno = lineno
        self.col_offset = col_offset
        self.factory = factory

    def to_dict(self):
        return {
            'uid': self.uid,
            'name': self.name,
            'lineno': self.lineno,
            'col_offset': self.col_offset,
            'factory': self.factory,
        }


ResourceEvidence = _Resource


class _State(object):
    __slots__ = (
        'pending',
        'completed',
        'handed_off',
        'unknown',
        'env',
        'checks',
        'call_aliases',
        'path',
        'cleanup',
        'depth',
    )

    def __init__(self, depth=0):
        self.pending = {}
        self.completed = set()
        self.handed_off = set()
        self.unknown = {}
        self.env = {}
        self.checks = {}
        self.call_aliases = {}
        self.path = []
        self.cleanup = []
        self.depth = depth

    def clone(self, depth=None):
        state = _State(self.depth if depth is None else depth)
        state.pending = dict(self.pending)
        state.completed = set(self.completed)
        state.handed_off = set(self.handed_off)
        state.unknown = dict(self.unknown)
        state.env = dict(self.env)
        state.checks = dict((key, set(value)) for key, value in self.checks.items())
        state.call_aliases = dict(self.call_aliases)
        state.path = list(self.path)
        state.cleanup = list(self.cleanup)
        return state

    def add_step(self, kind, node, detail=''):
        self.path.append(PathStep(
            kind,
            getattr(node, 'lineno', 0),
            getattr(node, 'col_offset', 0),
            detail,
        ))

    def update_from(self, other):
        self.pending = dict(other.pending)
        self.completed = set(other.completed)
        self.handed_off = set(other.handed_off)
        self.unknown = dict(other.unknown)
        self.env = dict(other.env)
        self.checks = dict((key, set(value)) for key, value in other.checks.items())
        self.call_aliases = dict(other.call_aliases)
        self.path = list(other.path)
        self.cleanup = list(other.cleanup)

    def live_resources(self):
        return dict(
            (uid, resource)
            for uid, resource in self.pending.items()
            if uid not in self.completed and uid not in self.handed_off
        )


class _Outcome(object):
    __slots__ = ('kind', 'state', 'node', 'detail')

    def __init__(self, kind, state, node=None, detail=''):
        self.kind = kind
        self.state = state
        self.node = node
        self.detail = detail


class _Resolver(object):
    """Resolve local import aliases without importing anything."""

    def __init__(self, module_node):
        self.aliases = {}
        self.wildcards = []
        if isinstance(module_node, ast.Module):
            self._collect(module_node.body)

    def _collect(self, statements):
        for statement in statements:
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    local = alias.asname or alias.name.split('.')[0]
                    self.aliases[local] = alias.name
            elif isinstance(statement, ast.ImportFrom):
                prefix = statement.module or ''
                for alias in statement.names:
                    if alias.name == '*':
                        self.wildcards.append(prefix)
                        continue
                    local = alias.asname or alias.name
                    self.aliases[local] = '.'.join(
                        part for part in (prefix, alias.name) if part)

    def canonical(self, node):
        path = _dotted(node)
        if not path:
            return ''
        first, _, rest = path.partition('.')
        if first in self.aliases:
            base = self.aliases[first]
            return '.'.join(part for part in (base, rest) if part)
        return path

    def matches(self, node, names):
        canonical = self.canonical(node)
        candidates = set(_match_candidates(canonical))
        candidates.add(_dotted(node))
        if isinstance(node, ast.Name):
            candidates.add(node.id)
        elif isinstance(node, ast.Attribute):
            candidates.add(node.attr)
        for name in names:
            if name in candidates:
                return True
            if any(candidate.endswith('.' + name) for candidate in candidates):
                return True
        return False


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted(node.value)
        return '.'.join(part for part in (prefix, node.attr) if part)
    return ''


def _literal_strings(node):
    if _AST_CONSTANT and isinstance(node, _AST_CONSTANT) and isinstance(node.value, str):
        return [node.value]
    if not _AST_CONSTANT and isinstance(node, ast.Str):
        return [node.s]
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        result = []
        for element in node.elts:
            result.extend(_literal_strings(element))
        return result
    if isinstance(node, ast.Dict):
        result = []
        for key in node.keys:
            result.extend(_literal_strings(key))
        for value in node.values:
            result.extend(_literal_strings(value))
        return result
    return []


def _decorator_name(decorator):
    if isinstance(decorator, ast.Call):
        return _dotted(decorator.func)
    return _dotted(decorator)


def _unwrap_await(node):
    if _AST_AWAIT and isinstance(node, _AST_AWAIT):
        return node.value
    return node


def _decorator_strings(decorator):
    if not isinstance(decorator, ast.Call):
        return []
    result = []
    for argument in decorator.args:
        result.extend(_literal_strings(argument))
    for keyword in decorator.keywords:
        result.extend(_literal_strings(keyword.value))
    return result


def _is_stub_body(body):
    if not body:
        return True
    meaningful = 0
    for statement in body:
        if isinstance(statement, ast.Pass):
            continue
        if isinstance(statement, ast.Expr):
            value = statement.value
            if _AST_CONSTANT and isinstance(value, _AST_CONSTANT) and isinstance(value.value, str):
                continue
            if not _AST_CONSTANT and isinstance(value, ast.Str):
                continue
            if _AST_CONSTANT and isinstance(value, _AST_CONSTANT) and value.value is Ellipsis:
                continue
            if not _AST_CONSTANT and isinstance(value, ast.Ellipsis):
                continue
        if isinstance(statement, ast.Raise):
            continue
        meaningful += 1
    return meaningful == 0


def _declaration_names(name, value, config):
    lower = name.lower()
    names = _literal_strings(value)
    if isinstance(value, ast.Dict) and any(
        marker in lower for marker in ('placeholder', 'stub', 'convention', 'declaration')
    ):
        mapping = {}
        for key, role in zip(value.keys, value.values):
            key_names = _literal_strings(key)
            role_names = _literal_strings(role)
            if key_names and role_names:
                mapping[key_names[0]] = role_names[0]
        _apply_role_mapping(mapping, config)
    if 'contract' in lower and isinstance(value, ast.Dict):
        declared = {}
        for key, contract in zip(value.keys, value.values):
            key_names = _literal_strings(key)
            contract_names = _literal_strings(contract)
            for key_name in key_names:
                if contract_names:
                    declared[key_name] = _contract_value(contract_names[0])
        config.contracts.update(declared)
    if 'placeholder' in lower or 'stub' in lower:
        config.placeholders = tuple(dict.fromkeys(config.placeholders + tuple(names)))
    if not names:
        return
    if any(marker in lower for marker in _FACTORY_DECLARATION_MARKERS):
        config.factories = tuple(dict.fromkeys(config.factories + tuple(names)))
    if any(marker in lower for marker in _HANDOFF_DECLARATION_MARKERS):
        config.handoffs = tuple(dict.fromkeys(config.handoffs + tuple(names)))
    if any(marker in lower for marker in _DECLARATION_MARKERS):
        config.checks = tuple(dict.fromkeys(config.checks + tuple(names)))


def make_module(body):
    """Build an ``ast.Module`` across supported Python generations."""

    try:
        return ast.Module(body=body, type_ignores=[])
    except TypeError:
        return ast.Module(body=body)


def _apply_declarations(module_node, config):
    if not isinstance(module_node, ast.Module):
        module_node = make_module([module_node])
    for statement in module_node.body:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    _declaration_names(target.id, statement.value, config)
        elif isinstance(statement, ast.AnnAssign):
            if isinstance(statement.target, ast.Name) and statement.value is not None:
                _declaration_names(statement.target.id, statement.value, config)
            if isinstance(statement.target, ast.Name):
                annotation = _dotted(statement.annotation) if statement.annotation else ''
                if any(marker in annotation.lower() for marker in _DECLARATION_MARKERS):
                    config.checks = tuple(
                        dict.fromkeys(config.checks + (statement.target.id,)))
        elif isinstance(statement, _FUNCTION_DEF_TYPES):
            if statement.returns is not None:
                returns = _dotted(statement.returns).lower()
                if returns in ('bool', 'boolean'):
                    config.contracts[statement.name] = CONTRACT_BOOL
                if _is_stub_body(statement.body) and returns in ('bool', 'boolean'):
                    config.checks = tuple(
                        dict.fromkeys(config.checks + (statement.name,)))
            for decorator in statement.decorator_list:
                name = _decorator_name(decorator).lower()
                if any(marker in name for marker in _DECLARATION_MARKERS):
                    if _is_stub_body(statement.body) or 'placeholder' in name or 'stub' in name:
                        config.checks = tuple(
                            dict.fromkeys(config.checks + (statement.name,)))
                for declared in _decorator_strings(decorator):
                    config.checks = tuple(
                        dict.fromkeys(config.checks + (declared,)))
                if isinstance(decorator, ast.Call):
                    for keyword in decorator.keywords:
                        if keyword.arg in ('contract', 'kind', 'type'):
                            values = _literal_strings(keyword.value)
                            if values:
                                config.contracts[statement.name] = _contract_value(values[0])
            for argument in _arguments(statement):
                annotation = _dotted(argument.annotation) if argument.annotation else ''
                if any(marker in annotation.lower() for marker in _DECLARATION_MARKERS):
                    config.checks = tuple(
                        dict.fromkeys(config.checks + (argument.arg,)))
    return config


def _apply_function_declarations(function_node, config):
    for decorator in getattr(function_node, 'decorator_list', []):
        name = _decorator_name(decorator)
        lower = name.lower()
        strings = _decorator_strings(decorator)
        if strings and any(marker in lower for marker in _DECLARATION_MARKERS):
            config.checks = tuple(dict.fromkeys(config.checks + tuple(strings)))
            if isinstance(decorator, ast.Call):
                for keyword in decorator.keywords:
                    if keyword.arg in ('contract', 'kind', 'type'):
                        values = _literal_strings(keyword.value)
                        for name in strings:
                            if values:
                                config.contracts[name] = _contract_value(values[0])
        if any(marker in lower for marker in ('resource', 'temporary', 'factory')):
            config.track_parameters = True
    return config


def _function_nodes(node):
    result = []
    for child in ast.walk(node):
        if isinstance(child, _FUNCTION_DEF_TYPES):
            result.append(child)
    result.sort(key=lambda item: (getattr(item, 'lineno', 0), getattr(item, 'col_offset', 0)))
    return result


class _Analyzer(object):
    def __init__(self, module_node, config):
        self.module_node = module_node
        self.config = _apply_declarations(module_node, config)
        self.resolver = _Resolver(module_node)
        self._uid = 0
        self._budget_exceeded = False
        self._current_resources = []

    def new_resource(self, call, targets):
        self._uid += 1
        name = ','.join(targets) if targets else '<temporary>'
        resource = _Resource(
            'tmp{}'.format(self._uid),
            name,
            getattr(call, 'lineno', 0),
            getattr(call, 'col_offset', 0),
            self.resolver.canonical(call.func) if isinstance(call, ast.Call) else '',
        )
        self._current_resources.append(resource)
        return resource

    def analyze_module(self):
        result = []
        for function in _function_nodes(self.module_node):
            function_evidence = self.analyze_function(function)
            if (
                function_evidence.resources
                or function_evidence.problems
                or function_evidence.budget_exceeded
            ):
                result.append(function_evidence)
        result.sort(key=lambda item: (item.lineno, item.col_offset, item.name))
        return result

    def analyze_function(self, function_node):
        config = _apply_function_declarations(function_node, self.config)
        state = _State()
        self._current_resources = []
        resources = []
        helper_names = set(config.factories) | set(config.checks) | set(config.handoffs)
        function_candidates = set(_match_candidates(getattr(function_node, 'name', '')))
        is_helper = bool(function_candidates & helper_names)
        if config.track_parameters and not is_helper and not _is_stub_body(function_node.body):
            for argument in _arguments(function_node):
                annotation = _dotted(argument.annotation) if argument.annotation else ''
                name = argument.arg
                if (
                    any(marker in annotation.lower() for marker in ('resource', 'temporary', 'tempfile'))
                    or _looks_like_resource_name(name)
                ):
                    self._uid += 1
                    resource = _Resource(
                        'tmp{}'.format(self._uid),
                        name,
                        getattr(argument, 'lineno', getattr(function_node, 'lineno', 0)),
                        getattr(argument, 'col_offset', 0),
                        '<parameter>',
                    )
                    state.pending[resource.uid] = resource
                    state.env[name] = resource.uid
                    resources.append(resource)

        outcomes = self._statements(function_node.body, state)
        if not any(outcome.kind == 'fall' for outcome in outcomes):
            # No fall-through: all exits are explicit terminators or the whole
            # body was a terminal statement.
            pass

        exits = []
        seen = set()
        last_line = _last_line(function_node)
        for outcome in outcomes:
            exit_evidence = self._classify(outcome, function_node, last_line)
            key = (
                exit_evidence.kind,
                exit_evidence.status,
                exit_evidence.lineno,
                exit_evidence.col_offset,
                exit_evidence.resource,
            )
            if key in seen:
                continue
            seen.add(key)
            exits.append(exit_evidence)
        for resource in self._current_resources:
            if resource not in resources:
                resources.append(resource)

        exits.sort(key=lambda item: (item.lineno, item.col_offset, item.status))
        return FunctionEvidence(
            getattr(function_node, 'name', '<function>'),
            getattr(function_node, 'lineno', 0),
            getattr(function_node, 'col_offset', 0),
            exits,
            resources,
            self._budget_exceeded,
        )

    def _classify(self, outcome, function_node, fallback_line):
        state = outcome.state
        live = state.live_resources()
        resources = sorted(live.values(), key=lambda item: item.uid)
        cleanup = state.cleanup[-1] if state.cleanup else None

        if not live:
            if state.completed and (outcome.kind == 'raise' or cleanup == 'except'):
                status = EXCEPTION_CLEANUP
                reason = 'resource released on a recognised exception path'
            elif state.handed_off and not state.completed:
                status = NORMAL
                reason = 'resource ownership handed off on this path'
                cleanup = 'handoff'
            else:
                status = NORMAL
                reason = 'security check completed on this path'
        else:
            unknown = [resource for resource in resources if resource.uid in state.unknown]
            if unknown:
                status = CONTRACT_UNKNOWN
                reason = state.unknown.get(unknown[0].uid, 'contract unknown')
            elif outcome.kind == 'raise':
                status = UNCHECKED_EXCEPTION
                reason = 'exception exit before the security check completed'
            else:
                status = UNCHECKED
                reason = 'return before the security check completed'

        node = outcome.node
        lineno = getattr(node, 'lineno', fallback_line)
        col_offset = getattr(node, 'col_offset', 0)
        if outcome.kind == 'fall':
            lineno = fallback_line
            col_offset = 0

        first = resources[0] if resources else None
        return ExitEvidence(
            outcome.kind,
            status,
            lineno,
            col_offset,
            resource=first.uid if first else None,
            resource_name=first.name if first else None,
            resources=tuple(resource.uid for resource in resources),
            reason=reason,
            evidence=tuple(state.path),
            cleanup=cleanup,
            factory=first.factory if first else None,
        )

    def _statements(self, statements, state):
        outcomes = [_Outcome('fall', state)]
        for statement in statements:
            next_outcomes = []
            for outcome in outcomes:
                if outcome.kind != 'fall':
                    next_outcomes.append(outcome)
                else:
                    next_outcomes.extend(self._statement(statement, outcome.state))
            outcomes = next_outcomes
            if len(outcomes) > self.config.max_paths:
                self._budget_exceeded = True
                merged = self._merge_outcomes(outcomes)
                outcomes = merged[:self.config.max_paths]
        return outcomes

    def _merge_outcomes(self, outcomes):
        result = []
        seen = set()
        for outcome in outcomes:
            state = outcome.state
            key = (
                outcome.kind,
                getattr(outcome.node, 'lineno', 0),
                getattr(outcome.node, 'col_offset', 0),
                outcome.detail,
                tuple(sorted(state.pending)),
                tuple(sorted(state.completed)),
                tuple(sorted(state.handed_off)),
                tuple(sorted(state.unknown)),
            )
            if key in seen:
                continue
            seen.add(key)
            result.append(outcome)
        return result

    def _statement(self, node, state):
        if isinstance(node, ast.If):
            return self._if(node, state)
        if isinstance(node, _LOOP_TYPES):
            return self._loop(node, state)
        if isinstance(node, _TRY_TYPES):
            return self._try(node, state)
        if _AST_MATCH and isinstance(node, _AST_MATCH):
            return self._match(node, state)
        if isinstance(node, _WITH_TYPES):
            return self._with(node, state)
        if isinstance(node, ast.Return):
            return self._return(node, state)
        if isinstance(node, ast.Raise):
            state.add_step('raise', node)
            if node.exc is not None:
                self._expression(node.exc, state)
            return [_Outcome('raise', state, node)]
        if isinstance(node, ast.Break):
            state.add_step('break', node)
            return [_Outcome('break', state, node)]
        if isinstance(node, ast.Continue):
            state.add_step('continue', node)
            return [_Outcome('continue', state, node)]
        if isinstance(node, _FUNCTION_DEF_TYPES + (ast.ClassDef,)):
            return [_Outcome('fall', state)]
        self._statement_expression(node, state)
        return [_Outcome('fall', state)]

    def _statement_expression(self, node, state):
        if isinstance(node, ast.Assign):
            value_state = state
            self._expression(node.value, value_state)
            value_refs = self._refs(node.value, value_state)
            for target in node.targets:
                for name in _target_names(target):
                    if value_state.env.get(name) not in value_refs:
                        self._invalidate_name(name, value_state)
            targets = []
            for target in node.targets:
                targets.extend(_target_names(target))
            self._bind_factory_or_alias(node.value, targets, value_state)
        elif isinstance(node, ast.AnnAssign):
            targets = _target_names(node.target)
            if node.value is not None:
                self._expression(node.value, state)
                value_refs = self._refs(node.value, state)
                for name in targets:
                    if state.env.get(name) not in value_refs:
                        self._invalidate_name(name, state)
                self._bind_factory_or_alias(node.value, targets, state)
            else:
                for name in targets:
                    self._invalidate_name(name, state)
        elif isinstance(node, ast.AugAssign):
            self._expression(node.value, state)
            self._expression(node.target, state)
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                for name in _target_names(target):
                    self._delete_name(name, state)
        elif isinstance(node, ast.Expr):
            self._expression(node.value, state)
        elif isinstance(node, (ast.Assert,)):
            true_state = state.clone()
            false_state = state.clone()
            self._test(node.test, state, true_state, false_state)
            self._expression(node.test, state)
            state.update_from(true_state)
        elif isinstance(node, (ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal)):
            pass
        else:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.expr):
                    self._expression(child, state)

    def _if(self, node, state):
        true_state = state.clone()
        false_state = state.clone()
        self._test(node.test, state, true_state, false_state)
        true_outcomes = self._statements(node.body, true_state)
        false_outcomes = self._statements(node.orelse, false_state)
        return self._merge_outcomes(true_outcomes + false_outcomes)

    def _loop(self, node, state):
        # A loop may execute zero times.  We also execute one bounded iteration
        # so cleanup inside the body is visible; further iterations are merged.
        zero_state = state.clone()
        zero_state.add_step('loop-skip', node)
        body_state = state.clone()
        if isinstance(node, (ast.For, _AST_ASYNC_FOR)):
            self._expression(node.iter, body_state)
            self._bind_loop_target(node.target, body_state)
        elif isinstance(node, ast.While):
            self._test(node.test, state, body_state, zero_state)
        body_outcomes = self._statements(node.body, body_state)
        outcomes = []
        for outcome in body_outcomes:
            if outcome.kind in ('break', 'fall'):
                out = _Outcome('fall', outcome.state.clone(), node)
                out.state.add_step('loop-exit', node)
                outcomes.append(out)
            elif outcome.kind == 'continue':
                out = _Outcome('fall', outcome.state.clone(), node)
                out.state.add_step('loop-continue', node)
                outcomes.append(out)
            else:
                outcomes.append(outcome)
        else_outcomes = self._statements(node.orelse, zero_state) if node.orelse else []
        outcomes.append(_Outcome('fall', zero_state, node, 'zero iterations'))
        outcomes.extend(else_outcomes)
        return self._merge_outcomes(outcomes)

    def _try(self, node, state):
        body_outcomes = self._statements(node.body, state.clone())
        normal_outcomes = [outcome for outcome in body_outcomes if outcome.kind == 'fall']
        abrupt_outcomes = [outcome for outcome in body_outcomes if outcome.kind != 'fall']

        if node.orelse:
            else_outcomes = []
            for outcome in normal_outcomes:
                else_outcomes.extend(self._statements(node.orelse, outcome.state))
            normal_outcomes = else_outcomes

        handler_outcomes = []
        prefix_states = self._prefix_states(node.body, state.clone())
        for handler in node.handlers:
            for prefix in prefix_states:
                handler_state = prefix.clone()
                handler_state.add_step('except', handler)
                handler_state.cleanup.append('except')
                handler_outcomes.extend(self._statements(handler.body, handler_state))

        if not _catch_all(node.handlers) and _body_can_raise(node.body):
            for prefix in prefix_states:
                exception_state = prefix.clone()
                exception_state.add_step('exception', node, 'uncaught')
                handler_outcomes.append(_Outcome(
                    'raise', exception_state, node, 'uncaught exception'))

        combined = normal_outcomes + abrupt_outcomes + handler_outcomes
        if node.finalbody:
            final_outcomes = []
            for outcome in combined:
                final_state = outcome.state.clone()
                terminal_steps = []
                if (
                    final_state.path
                    and final_state.path[-1].kind == outcome.kind
                ):
                    terminal_steps.append(final_state.path.pop())
                final_state.add_step('finally', node)
                final_state.cleanup.append('finally')
                final_results = self._statements(node.finalbody, final_state)
                for result in final_results:
                    if result.kind == 'fall':
                        result.state.path.extend(terminal_steps)
                        final_outcomes.append(_Outcome(
                            outcome.kind,
                            result.state,
                            outcome.node,
                            outcome.detail,
                        ))
                    else:
                        final_outcomes.append(result)
            combined = final_outcomes
        return self._merge_outcomes(combined)

    def _match(self, node, state):
        self._expression(node.subject, state)
        outcomes = []
        wildcard = False
        for case in node.cases:
            case_state = state.clone()
            case_state.add_step('match', case.pattern, 'case')
            if case.guard is not None:
                self._expression(case.guard, case_state)
            outcomes.extend(self._statements(case.body, case_state))
            if isinstance(case.pattern, getattr(ast, 'MatchAs', ())):
                if getattr(case.pattern, 'pattern', None) is None and case.guard is None:
                    wildcard = True
        if not wildcard:
            outcomes.append(_Outcome('fall', state.clone(), node, 'no match'))
        return self._merge_outcomes(outcomes)

    def _prefix_states(self, statements, state):
        prefixes = [state]
        current_states = [state]
        for statement in statements:
            next_states = []
            for current_state in current_states:
                next_states.extend(
                    item.state for item in self._statement(statement, current_state.clone())
                    if item.kind == 'fall'
                )
            if not next_states:
                break
            prefixes.extend(next_states)
            current_states = next_states
            if len(prefixes) > self.config.max_paths:
                self._budget_exceeded = True
                break
        unique = []
        seen = set()
        for prefix in prefixes:
            key = (
                tuple(sorted(prefix.pending)),
                tuple(sorted(prefix.completed)),
                tuple(sorted(prefix.unknown)),
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(prefix)
        return unique

    def _with(self, node, state):
        body_state = state.clone()
        context_resources = []
        context_checks = []
        for item in node.items:
            self._expression(item.context_expr, body_state)
            targets = _target_names(item.optional_vars)
            target = targets[0] if targets else ''
            if isinstance(item.context_expr, ast.Call) and self._call_matches(
                item.context_expr.func, body_state, self.config.factories
            ):
                resource = self.new_resource(item.context_expr, [target] if target else [])
                body_state.pending[resource.uid] = resource
                for target_name in targets:
                    body_state.env[target_name] = resource.uid
                context_resources.append(resource)
            elif isinstance(item.context_expr, ast.Call) and self._call_matches(
                item.context_expr.func, body_state, self.config.checks
            ):
                context_checks.append(item.context_expr)
            elif target and target in body_state.env:
                context_resources.append(body_state.pending.get(body_state.env[target]))
        body_state.add_step('with', node)
        body_state.cleanup.append('with')
        outcomes = self._statements(node.body, body_state)
        result = []
        for outcome in outcomes:
            for check in context_checks:
                self._complete_refs(check, outcome.state)
            for resource in context_resources:
                if resource is not None:
                    outcome.state.completed.add(resource.uid)
            result.append(outcome)
        return result

    def _return(self, node, state):
        if isinstance(node.value, ast.IfExp):
            true_state = state.clone()
            false_state = state.clone()
            self._test(node.value.test, state, true_state, false_state)
            outcomes = []
            for branch_state, branch_value in (
                (true_state, node.value.body),
                (false_state, node.value.orelse),
            ):
                self._expression(branch_value, branch_state)
                self._handle_return_value(branch_value, branch_state)
                branch_state.add_step('return', node)
                outcomes.append(_Outcome('return', branch_state, node))
            return outcomes
        if node.value is not None:
            self._expression(node.value, state)
            self._handle_return_value(node.value, state)
        state.add_step('return', node)
        return [_Outcome('return', state, node)]

    def _handle_return_value(self, value, state):
        value = _unwrap_await(value)
        if isinstance(value, ast.Call):
            name = self.resolver.canonical(value.func)
            if self._call_matches(value.func, state, self.config.checks):
                contract = self.config.contract_for(name)
                if contract in (CONTRACT_RAISES, CONTRACT_RETURNS, CONTRACT_BOOL):
                    self._complete_refs(value, state)
            elif self._call_matches(value.func, state, self.config.handoffs):
                self._handoff_refs(value, state)

    def _expression(self, node, state):
        if node is None:
            return state
        if isinstance(node, ast.Call):
            for argument in list(node.args) + [keyword.value for keyword in node.keywords]:
                self._expression(argument, state)
            if isinstance(node.func, ast.Attribute):
                self._expression(node.func.value, state)
            self._call(node, state)
        elif isinstance(node, ast.Lambda):
            # A lambda body is not executed at definition time.
            return state
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            for generator in node.generators:
                self._expression(generator.iter, state)
                self._expression(generator.target, state)
                for condition in generator.ifs:
                    self._expression(condition, state)
            self._expression(getattr(node, 'elt', None), state)
            self._expression(getattr(node, 'key', None), state)
            self._expression(getattr(node, 'value', None), state)
        elif isinstance(node, ast.BoolOp):
            for value in node.values:
                self._expression(value, state)
        elif isinstance(node, ast.Compare):
            self._expression(node.left, state)
            for comparator in node.comparators:
                self._expression(comparator, state)
        elif isinstance(node, ast.IfExp):
            self._expression(node.test, state)
            self._expression(node.body, state)
            self._expression(node.orelse, state)
        elif _AST_NAMED_EXPR and isinstance(node, _AST_NAMED_EXPR):
            self._expression(node.value, state)
        else:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.expr):
                    self._expression(child, state)
        return state

    def _call(self, call, state):
        name = self.resolver.canonical(call.func)
        func = call.func
        if self._call_matches(func, state, self.config.factories):
            return
        if self._call_matches(func, state, self.config.checks):
            contract = self.config.contract_for(name)
            state.add_step('check', call, name)
            if contract == CONTRACT_RAISES:
                self._complete_refs(call, state)
            else:
                # BOOL/RETURNS checks only prove their result when a branch or
                # the caller consumes that result.  Assignment handling records
                # the result below; a bare call deliberately does not complete.
                pass
            return
        if self._call_matches(func, state, self.config.handoffs):
            state.add_step('handoff', call, name)
            self._handoff_refs(call, state)
            return

        refs = self._call_refs(call, state)
        if refs:
            for uid in refs:
                if uid in state.pending and uid not in state.completed:
                    state.unknown[uid] = (
                        'call to "{}" has no recognised check/handoff contract'
                        .format(name or _dotted(func) or '<call>')
                    )
                    state.add_step('unknown', call, name)

    def _call_matches(self, func, state, names):
        if self.resolver.matches(func, names):
            return True
        alias = state.call_aliases.get(_dotted(func))
        if not alias:
            return False
        return bool(set(_match_candidates(alias)) & set(names))

    def _test(self, test, entry_state, true_state, false_state):
        direct = _unwrap_await(test)
        negated = False
        while isinstance(direct, ast.UnaryOp) and isinstance(direct.op, ast.Not):
            negated = not negated
            direct = direct.operand

        if isinstance(direct, ast.Compare) and len(direct.ops) == 1:
            op = direct.ops[0]
            if isinstance(op, (ast.Is, ast.IsNot, ast.Eq, ast.NotEq)):
                if _AST_CONSTANT and isinstance(direct.comparators[0], _AST_CONSTANT):
                    value = direct.comparators[0].value
                    if value is True or value is False:
                        if value is False:
                            negated = not negated
                        if isinstance(op, (ast.IsNot, ast.NotEq)):
                            negated = not negated
                        direct = direct.left
                elif isinstance(direct.comparators[0], ast.Name):
                    if direct.comparators[0].id in ('True', 'False'):
                        if direct.comparators[0].id == 'False':
                            negated = not negated
                        if isinstance(op, (ast.IsNot, ast.NotEq)):
                            negated = not negated
                        direct = direct.left

        if isinstance(direct, ast.Call):
            name = self.resolver.canonical(direct.func)
            if self._call_matches(direct.func, entry_state, self.config.checks):
                contract = self.config.contract_for(name)
                if contract in (CONTRACT_RAISES,):
                    self._complete_refs(direct, true_state)
                    self._complete_refs(direct, false_state)
                else:
                    proof = false_state if negated else true_state
                    self._complete_refs(direct, proof)
                return
            if isinstance(direct.func, ast.Name) and direct.func.id in entry_state.checks:
                uids = entry_state.checks[direct.func.id]
                proof = false_state if negated else true_state
                proof.completed.update(uids)
                return
            refs = self._call_refs(direct, entry_state)
            if refs:
                for uid in refs:
                    true_state.unknown.setdefault(uid, 'condition call contract unknown')
                    false_state.unknown.setdefault(uid, 'condition call contract unknown')
            return

        if isinstance(direct, ast.Name) and direct.id in entry_state.checks:
            uids = entry_state.checks[direct.id]
            proof = false_state if negated else true_state
            proof.completed.update(uids)
            return

        if isinstance(direct, ast.BoolOp):
            # Conservative: an ``and`` chain only proves its checks on the
            # truthy path; an ``or`` chain only proves them after all operands.
            if isinstance(direct.op, ast.And):
                for value in direct.values:
                    self._test(value, entry_state, true_state, false_state)
            else:
                for value in direct.values:
                    self._test(value, entry_state, true_state, true_state)
            return

        self._expression(test, entry_state)

    def _complete_refs(self, call, state):
        refs = self._call_refs(call, state)
        if not refs:
            refs = set(state.live_resources())
        for uid in refs:
            if uid in state.pending:
                state.completed.add(uid)
                state.unknown.pop(uid, None)

    def _handoff_refs(self, call, state):
        refs = self._call_refs(call, state)
        if not refs:
            refs = set(state.live_resources())
        for uid in refs:
            if uid in state.pending:
                state.handed_off.add(uid)
                state.unknown.pop(uid, None)

    def _call_refs(self, call, state):
        refs = set()
        for argument in list(call.args) + [keyword.value for keyword in call.keywords]:
            refs.update(self._refs(argument, state))
        if isinstance(call.func, ast.Attribute):
            refs.update(self._refs(call.func.value, state))
        return refs

    def _refs(self, node, state):
        if node is None:
            return set()
        if isinstance(node, ast.Name):
            uid = state.env.get(node.id)
            return {uid} if uid in state.pending else set()
        if isinstance(node, ast.Attribute):
            name = _dotted(node)
            uid = state.env.get(name)
            if uid in state.pending:
                return {uid}
            return self._refs(node.value, state)
        if isinstance(node, ast.Subscript):
            uid = state.env.get(_target_name(node))
            if uid in state.pending:
                return {uid}
            return self._refs(node.value, state)
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            result = set()
            for element in node.elts:
                result.update(self._refs(element, state))
            return result
        if isinstance(node, ast.Starred):
            return self._refs(node.value, state)
        if isinstance(node, ast.Call):
            result = set()
            for argument in list(node.args) + [keyword.value for keyword in node.keywords]:
                result.update(self._refs(argument, state))
            return result
        return set()

    def _bind_factory_or_alias(self, value, targets, state):
        call_value = _unwrap_await(value)
        if isinstance(call_value, ast.Call) and self._call_matches(
            call_value.func, state, self.config.factories
        ):
            resource = self.new_resource(call_value, [target for target in targets if target])
            state.pending[resource.uid] = resource
            state.add_step('acquire', call_value, resource.name)
            for target in targets:
                if target:
                    state.env[target] = resource.uid
            return

        if isinstance(call_value, ast.Call) and self._call_matches(
            call_value.func, state, self.config.checks
        ):
            name = self.resolver.canonical(call_value.func)
            contract = self.config.contract_for(name)
            refs = self._call_refs(call_value, state)
            if contract == CONTRACT_BOOL:
                for target in targets:
                    if target:
                        state.checks[target] = set(refs)
            elif contract == CONTRACT_RETURNS:
                for target in targets:
                    if target:
                        state.env[target] = sorted(refs)[0] if refs else None
            return

        if isinstance(value, ast.Dict) and len(targets) == 1 and targets[0]:
            for key, item in zip(value.keys, value.values):
                item_refs = self._refs(item, state)
                key_name = _target_name(key)
                if item_refs and key_name:
                    state.env['{}[{}]'.format(targets[0], key_name)] = sorted(item_refs)[0]
            return
        if isinstance(value, (ast.List, ast.Tuple)) and len(targets) == 1 and targets[0]:
            for index, item in enumerate(value.elts):
                item_refs = self._refs(item, state)
                if item_refs:
                    state.env['{}[{}]'.format(targets[0], index)] = sorted(item_refs)[0]
            return

        refs = self._refs(call_value, state)
        if refs:
            uid = sorted(refs)[0]
            for target in targets:
                if target:
                    state.env[target] = uid
            return

        for target in targets:
            if target:
                state.env.pop(target, None)
                state.checks.pop(target, None)

        if isinstance(value, (ast.Name, ast.Attribute)):
            canonical = self.resolver.canonical(value)
            if (
                self.resolver.matches(value, self.config.checks)
                or self.resolver.matches(value, self.config.factories)
                or self.resolver.matches(value, self.config.handoffs)
            ):
                for target in targets:
                    if target:
                        state.call_aliases[target] = canonical
                return
        for target in targets:
            if target:
                state.call_aliases.pop(target, None)

    def _bind_loop_target(self, target, state):
        for name in _target_names(target):
            state.env.pop(name, None)

    def _invalidate_name(self, name, state):
        if not name:
            return
        old = state.env.get(name)
        if old in state.pending and old not in state.completed:
            # Reassignment without a check loses the original resource.  A
            # later return will still be the first readable divergence, so we
            # keep the resource pending rather than inventing a second alert.
            state.unknown.setdefault(
                old,
                'resource binding was overwritten before the check completed',
            )
        state.call_aliases.pop(name, None)

    def _delete_name(self, name, state):
        if not name:
            return
        uid = state.env.get(name)
        if uid in state.pending:
            state.unknown.setdefault(uid, 'resource binding was deleted')
        state.env.pop(name, None)
        state.checks.pop(name, None)
        state.call_aliases.pop(name, None)


def _arguments(function_node):
    args = getattr(function_node, 'args', None)
    if args is None:
        return []
    result = list(getattr(args, 'posonlyargs', []) or [])
    result.extend(getattr(args, 'args', []) or [])
    result.extend(getattr(args, 'vararg', None) and [args.vararg] or [])
    result.extend(getattr(args, 'kwonlyargs', []) or [])
    result.extend(getattr(args, 'kwarg', None) and [args.kwarg] or [])
    return result


def _looks_like_resource_name(name):
    lower = (name or '').lower()
    return (
        lower in (
            'res', 'resource', 'temp', 'temporary', 'tempfile', 'tmp',
        )
        or lower.startswith((
            'res_', 'resource_', 'temp_', 'temporary_', 'tempfile_', 'tmp_',
        ))
    )


def _target_name(node):
    if node is None:
        return ''
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _dotted(node)
    if isinstance(node, ast.Subscript):
        value = _target_name(node.value)
        key = _target_name(node.slice)
        if value and key:
            return '{}[{}]'.format(value, key)
        return value
    if _AST_CONSTANT and isinstance(node, _AST_CONSTANT):
        if isinstance(node.value, str):
            return node.value
        if isinstance(node.value, (int, float)):
            return str(node.value)
    if not _AST_CONSTANT and isinstance(node, ast.Str):
        return node.s
    if not _AST_CONSTANT and isinstance(node, ast.Num):
        return str(node.n)
    if isinstance(node, (ast.Tuple, ast.List)):
        return ','.join(_target_name(element) for element in node.elts)
    return ''


def _target_names(node):
    if node is None:
        return []
    if isinstance(node, (ast.Tuple, ast.List)):
        result = []
        for element in node.elts:
            result.extend(_target_names(element))
        return result
    name = _target_name(node)
    return [name] if name else []


def _last_line(function_node):
    body = getattr(function_node, 'body', [])
    if not body:
        return getattr(function_node, 'lineno', 0)
    last = body[-1]
    end_lineno = getattr(last, 'end_lineno', None)
    if end_lineno:
        return end_lineno
    return getattr(last, 'lineno', getattr(function_node, 'lineno', 0))


def _body_can_raise(statements):
    for statement in statements:
        for node in ast.walk(statement):
            if isinstance(node, ast.Call):
                return True
            if _AST_AWAIT and isinstance(node, _AST_AWAIT):
                return True
            if isinstance(node, (ast.Raise, ast.Assert)):
                return True
    return False


def _catch_all(handlers):
    for handler in handlers:
        if handler.type is None:
            return True
        name = _dotted(handler.type).lower()
        if name in ('exception', 'baseexception', 'builtins.exception'):
            return True
    return False


def analyze_function(function_node, config=None, module_node=None, **kwargs):
    """Analyze one parsed function and return :class:`FunctionEvidence`."""

    if isinstance(function_node, str):
        parsed = ast.parse(textwrap.dedent(function_node))
        function_node = next(
            node for node in parsed.body
            if isinstance(node, _FUNCTION_DEF_TYPES)
        )
    if isinstance(config, dict):
        config = AnalysisConfig(**config)
    if config is None:
        config = AnalysisConfig()
    if kwargs:
        values = {
            'factories': config.factories,
            'checks': config.checks,
            'handoffs': config.handoffs,
            'contracts': config.contracts,
            'placeholders': config.placeholders,
            'conventions': config.conventions,
            'track_parameters': config.track_parameters,
            'report_unknown': config.report_unknown,
            'max_paths': config.max_paths,
            'max_loop_iterations': config.max_loop_iterations,
        }
        values.update(kwargs)
        config = AnalysisConfig(**values)
    if module_node is None:
        module_node = make_module([function_node])
    return _Analyzer(module_node, config).analyze_function(function_node)


def analyze_module(module_node, config=None, **kwargs):
    """Analyze every local function in ``module_node``."""

    if isinstance(module_node, str):
        module_node = ast.parse(textwrap.dedent(module_node))
    if isinstance(config, dict):
        config = AnalysisConfig(**config)
    if config is None:
        config = AnalysisConfig()
    if kwargs:
        values = {
            'factories': config.factories,
            'checks': config.checks,
            'handoffs': config.handoffs,
            'contracts': config.contracts,
            'placeholders': config.placeholders,
            'conventions': config.conventions,
            'track_parameters': config.track_parameters,
            'report_unknown': config.report_unknown,
            'max_paths': config.max_paths,
            'max_loop_iterations': config.max_loop_iterations,
        }
        values.update(kwargs)
        config = AnalysisConfig(**values)
    if not isinstance(module_node, ast.Module):
        module_node = make_module([module_node])
    return _Analyzer(module_node, config).analyze_module()


def collect_evidence(node, config=None, **kwargs):
    """Collect evidence from a module or a single function node."""

    if isinstance(node, str):
        node = ast.parse(textwrap.dedent(node))
    if isinstance(node, _FUNCTION_DEF_TYPES):
        return [analyze_function(node, config, **kwargs)]
    return analyze_module(node, config, **kwargs)


collect_branch_evidence = collect_evidence
branch_evidence = collect_evidence
analyze_branches = analyze_module
analyze_resource = analyze_function


__all__ = [
    'CONTRACT_UNKNOWN',
    'EXCEPTION_CLEANUP',
    'NORMAL',
    'UNCHECKED',
    'UNCHECKED_EXCEPTION',
    'NORMAL_RETURN',
    'RECOGNIZED_EXCEPTION_CLEANUP',
    'UNKNOWN_CONTRACT',
    'UNCHECKED_RETURN',
    'ExitKind',
    'Status',
    'AnalysisConfig',
    'ExitEvidence',
    'FunctionEvidence',
    'ResourceEvidence',
    'Finding',
    'PathStep',
    'analyze_function',
    'analyze_module',
    'collect_evidence',
    'collect_branch_evidence',
    'branch_evidence',
    'analyze_branches',
    'analyze_resource',
    'make_module',
]
