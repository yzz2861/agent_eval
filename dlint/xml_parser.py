#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast
import collections

from . import tree


IMPORT_BUILD_TIME = 'import_build_time'
PER_REQUEST = 'per_request'
UNKNOWN = 'unknown'

IMPORT_TIME = IMPORT_BUILD_TIME
BUILD_TIME = IMPORT_BUILD_TIME
IMPORT = IMPORT_BUILD_TIME
REQUEST_TIME = PER_REQUEST
REQUEST = PER_REQUEST
UNDETERMINED = UNKNOWN

SCOPES = (
    IMPORT_BUILD_TIME,
    PER_REQUEST,
    UNKNOWN,
)

ENTRY_POINTS = (
    'fromstring',
    'iterparse',
    'parse',
)

SECURE_FACTORY_MODULES = (
    'defusedxml.ElementTree',
    'defusedxml.cElementTree',
    'defusedxml.lxml',
)

INSECURE_FACTORY_MODULES = (
    'xml.etree.ElementTree',
    'xml.etree.cElementTree',
    'lxml.etree',
    'xml.dom.minidom',
    'xml.sax',
    'xmlrpclib',
)

_PARSER_CLASS_NAMES = (
    'DefusedXMLParser',
    'XMLParser',
    'XMLPullParser',
)


def _module_matches(module_path, candidates):
    return any(
        module_path == candidate
        or module_path.startswith(candidate + '.')
        for candidate in candidates
    )


def is_secure_factory_module(module_path):
    return _module_matches(module_path, SECURE_FACTORY_MODULES)


def is_insecure_factory_module(module_path):
    if module_path == 'xml.sax.saxutils' or module_path.startswith('xml.sax.saxutils.'):
        return False
    return _module_matches(module_path, INSECURE_FACTORY_MODULES)


def _entry_point(module_path):
    name = module_path.rsplit('.', 1)[-1]
    if name in ENTRY_POINTS:
        return name
    return None


def _literal_bool(node):
    if isinstance(node, ast.Name):
        if node.id == 'True':
            return True
        if node.id == 'False':
            return False
        if node.id == 'None':
            return None

    try:
        constant_type = ast.Constant
    except AttributeError:
        constant_type = ast.NameConstant

    if isinstance(node, constant_type):
        value = node.value if hasattr(node, 'value') else getattr(node, 's', None)
        if value is True or value is False:
            return value
        if value is None:
            return False

    return None


_MISSING = object()


def _kwarg_value(call, name):
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return _MISSING


def _has_kwargs_unpacking(call):
    return any(keyword.arg is None for keyword in call.keywords)


def _defusedxml_call_secure(call):
    forbid_dtd = _kwarg_value(call, 'forbid_dtd')
    forbid_entities = _kwarg_value(call, 'forbid_entities')
    forbid_external = _kwarg_value(call, 'forbid_external')

    if forbid_dtd is _MISSING:
        if _has_kwargs_unpacking(call):
            return None
        return False

    dtd = _literal_bool(forbid_dtd)
    if dtd is not True:
        return dtd

    for value in (forbid_entities, forbid_external):
        if value is _MISSING:
            continue

        defense = _literal_bool(value)
        if defense is not True:
            return defense

    return True


def _lxml_parser_secure(call):
    resolve_entities = _kwarg_value(call, 'resolve_entities')
    no_network = _kwarg_value(call, 'no_network')

    if resolve_entities is _MISSING or no_network is _MISSING:
        return False

    entities = _literal_bool(resolve_entities)
    network = _literal_bool(no_network)
    if entities is not False or network is not True:
        return False if entities is True or network is False else None

    for name in ('load_dtd', 'dtd_validation', 'huge_tree'):
        value = _kwarg_value(call, name)
        if value is _MISSING:
            continue

        enabled = _literal_bool(value)
        if enabled is True:
            return False
        if enabled is None:
            return None

    return True


class ImportBinding(object):
    def __init__(
            self,
            local_name,
            module_path,
            node,
            function_depth=0,
            fallback_main_path=None,
            fallback_node=None,
            whole_path_import=False):
        self.local_name = local_name
        self.module_path = module_path
        self.node = node
        self.function_depth = function_depth
        self.fallback_main_path = fallback_main_path
        self.fallback_node = fallback_node
        self.whole_path_import = whole_path_import

    @property
    def is_fallback(self):
        return self.fallback_node is not None

    @property
    def fallback_lineno(self):
        if self.fallback_node is None:
            return None
        return self.fallback_node.lineno

    @property
    def fallback_col_offset(self):
        if self.fallback_node is None:
            return None
        return self.fallback_node.col_offset


class ParserConfig(object):
    def __init__(self, name, secure, scope, node, module_path=None):
        self.name = name
        self.secure = secure
        self.scope = scope
        self.node = node
        self.module_path = module_path


class XMLParserDecision(object):
    def __init__(
            self,
            entry_point,
            scope,
            secure,
            lineno,
            col_offset,
            module_path=None,
            fallback=False,
            fallback_lineno=None,
            fallback_col_offset=None,
            reason=None,
            call_lineno=None,
            call_col_offset=None):
        self.entry_point = entry_point
        self.scope = scope
        self.secure = secure
        self.lineno = lineno
        self.col_offset = col_offset
        self.module_path = module_path
        self.fallback = fallback
        self.fallback_lineno = fallback_lineno
        self.fallback_col_offset = fallback_col_offset
        self.reason = reason
        self.call_lineno = call_lineno
        self.call_col_offset = call_col_offset

    @property
    def location(self):
        return (self.lineno, self.col_offset)

    @property
    def fallback_location(self):
        if not self.fallback:
            return None
        return (self.fallback_lineno, self.fallback_col_offset)

    @property
    def security(self):
        if self.secure is True:
            return 'secure'
        elif self.secure is False:
            return 'insecure'
        return 'unknown'

    @property
    def decision(self):
        return self.security

    def to_dict(self):
        return collections.OrderedDict([
            ('entry_point', self.entry_point),
            ('scope', self.scope),
            ('security', self.security),
            ('module_path', self.module_path),
            ('fallback', self.fallback),
            ('lineno', self.lineno),
            ('col_offset', self.col_offset),
            ('fallback_lineno', self.fallback_lineno),
            ('fallback_col_offset', self.fallback_col_offset),
            ('reason', self.reason),
        ])


_SCOPE_ALIASES = {
    "import": IMPORT_BUILD_TIME,
    "import_time": IMPORT_BUILD_TIME,
    "build": IMPORT_BUILD_TIME,
    "build_time": IMPORT_BUILD_TIME,
    "import_build": IMPORT_BUILD_TIME,
    "request": PER_REQUEST,
    "per-request": PER_REQUEST,
    "undetermined": UNKNOWN,
    "cannot_determine": UNKNOWN,
}


def _normalize_scope(scope):
    return _SCOPE_ALIASES.get(scope, scope)


class _EntryPointDecisions(list):
    def __getitem__(self, item):
        if isinstance(item, str):
            scope = _normalize_scope(item)
            return [
                decision for decision in self
                if decision.scope == scope
            ]
        return list.__getitem__(self, item)

    def get(self, scope, default=None):
        normalized = _normalize_scope(scope)
        if normalized not in SCOPES:
            return default
        return self[normalized]


class XMLParserSummary(object):
    def __init__(self, decisions, entry_points=ENTRY_POINTS):
        self.entry_points = tuple(entry_points)
        self.decisions = list(decisions)
        self.by_entry_point = collections.OrderedDict(
            (entry_point, _EntryPointDecisions())
            for entry_point in self.entry_points
        )

        for decision in self.decisions:
            entry_point = decision.entry_point
            if entry_point is None:
                continue
            self.by_entry_point.setdefault(entry_point, []).append(decision)

    @property
    def by_scope(self):
        return collections.OrderedDict(
            (
                scope,
                [
                    decision for decision in self.decisions
                    if decision.scope == scope
                ],
            )
            for scope in SCOPES
        )

    @property
    def import_build_time(self):
        return [
            decision for decision in self.decisions
            if decision.scope == IMPORT_BUILD_TIME
        ]

    @property
    def per_request(self):
        return [
            decision for decision in self.decisions
            if decision.scope == PER_REQUEST
        ]

    @property
    def unknown(self):
        return [
            decision for decision in self.decisions
            if decision.scope == UNKNOWN
        ]

    def findings(self):
        return [
            decision for decision in self.decisions
            if decision.secure is not True
        ]

    def counts(self):
        counts = collections.OrderedDict()
        for entry_point in self.entry_points:
            counts[entry_point] = collections.OrderedDict(
                (scope, {
                    'secure': 0,
                    'insecure': 0,
                    'unknown': 0,
                    'total': 0,
                })
                for scope in SCOPES
            )

        for decision in self.decisions:
            if decision.entry_point not in counts:
                continue
            count = counts[decision.entry_point][decision.scope]
            count[decision.security] += 1
            count['total'] += 1

        return counts

    def to_dict(self):
        return collections.OrderedDict([
            ('entry_points', collections.OrderedDict(
                (
                    entry_point,
                    collections.OrderedDict(
                        (
                            scope,
                            [
                                decision.to_dict()
                                for decision in decisions
                                if decision.scope == scope
                            ],
                        )
                        for scope in SCOPES
                    ),
                )
                for entry_point, decisions in self.by_entry_point.items()
            )),
            (IMPORT_BUILD_TIME, [
                decision.to_dict()
                for decision in self.import_build_time
            ]),
            (PER_REQUEST, [
                decision.to_dict()
                for decision in self.per_request
            ]),
            (UNKNOWN, [
                decision.to_dict()
                for decision in self.unknown
            ]),
        ])

    def as_dict(self):
        return self.to_dict()

    def __getitem__(self, key):
        if key in self.by_entry_point:
            return self.by_entry_point[key]
        return getattr(self, key)

    def __len__(self):
        return len(self.by_entry_point)

    def __iter__(self):
        return iter(self.by_entry_point)

    def get(self, key, default=None):
        return self.by_entry_point.get(key, default)

    def keys(self):
        return self.by_entry_point.keys()

    def values(self):
        return self.by_entry_point.values()

    def items(self):
        return self.by_entry_point.items()

    def render(self):
        lines = ['XML parser decision summary']
        counts = self.counts()

        for entry_point in self.entry_points:
            scopes = []
            for scope in SCOPES:
                count = counts[entry_point][scope]
                scopes.append(
                    '{}={} (secure={}, insecure={}, unknown={})'.format(
                        scope,
                        count['total'],
                        count['secure'],
                        count['insecure'],
                        count['unknown'],
                    )
                )
            lines.append('{}: {}'.format(entry_point, '; '.join(scopes)))

        return '\n'.join(lines)


class _ImportOccurrence(object):
    def __init__(
            self,
            local_name,
            module_path,
            node,
            function_depth,
            handler_try=None,
            body_try=None,
            whole_path_import=False):
        self.local_name = local_name
        self.module_path = module_path
        self.node = node
        self.function_depth = function_depth
        self.handler_try = handler_try
        self.body_try = body_try
        self.whole_path_import = whole_path_import
        self.fallback_main_path = None


class _CallOccurrence(object):
    def __init__(self, node, function_depth):
        self.node = node
        self.function_depth = function_depth


class _AssignmentOccurrence(object):
    def __init__(self, name, node, value, function_depth):
        self.name = name
        self.node = node
        self.value = value
        self.function_depth = function_depth


class _Collector(object):
    def __init__(self):
        self.imports = []
        self.calls = []
        self.assignments = []
        self.tries = []
        self.function_names = set()
        self.function_nodes = collections.OrderedDict()

    def collect(self, module_node):
        self._visit(module_node, 0, None, None)
        return self

    def _visit(self, node, function_depth, handler_try, body_try):
        if isinstance(node, _FUNCTION_NODES):
            self.function_names.add(node.name)
            self.function_nodes.setdefault(node.name, node)

            for child in node.decorator_list:
                self._visit(child, function_depth, handler_try, body_try)

            arguments = getattr(node, 'args', None)
            if arguments is not None:
                for child in _argument_nodes(arguments):
                    self._visit(child, function_depth, handler_try, body_try)

            for child in node.body:
                self._visit(child, function_depth + 1, handler_try, body_try)
            return

        if isinstance(node, _TRY_NODES):
            self.tries.append(node)

            for child in node.body:
                self._visit(child, function_depth, None, node)
            for handler in node.handlers:
                self._visit(handler, function_depth, node, None)
            for child in node.orelse:
                self._visit(child, function_depth, handler_try, None)
            for child in node.finalbody:
                self._visit(child, function_depth, handler_try, None)
            return

        if isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname or alias.name.split('.')[0]
                self.imports.append(
                    _ImportOccurrence(
                        local_name,
                        alias.name,
                        node,
                        function_depth,
                        handler_try,
                        body_try,
                        whole_path_import=alias.asname is None,
                    )
                )
            return

        if isinstance(node, ast.ImportFrom):
            if node.level or not node.module:
                return

            for alias in node.names:
                self.imports.append(
                    _ImportOccurrence(
                        alias.asname or alias.name,
                        node.module + '.' + alias.name,
                        node,
                        function_depth,
                        handler_try,
                        body_try,
                    )
                )
            return

        if isinstance(node, ast.Call):
            self.calls.append(_CallOccurrence(node, function_depth))

        elif isinstance(node, ast.Assign):
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                self.assignments.append(
                    _AssignmentOccurrence(
                        node.targets[0].id,
                        node,
                        node.value,
                        function_depth,
                    )
                )

        elif hasattr(ast, 'AnnAssign') and isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.value is not None:
                self.assignments.append(
                    _AssignmentOccurrence(
                        node.target.id,
                        node,
                        node.value,
                        function_depth,
                    )
                )

        for child in ast.iter_child_nodes(node):
            self._visit(child, function_depth, handler_try, body_try)


_FUNCTION_NODES = (ast.FunctionDef,)
if hasattr(ast, 'AsyncFunctionDef'):
    _FUNCTION_NODES += (ast.AsyncFunctionDef,)

_TRY_NODES = (ast.Try,)
if hasattr(ast, 'TryStar'):
    _TRY_NODES += (ast.TryStar,)


def _argument_nodes(arguments):
    nodes = list(getattr(arguments, 'defaults', []))
    nodes.extend(
        default
        for default in getattr(arguments, 'kw_defaults', [])
        if default is not None
    )
    return nodes


class _Analyzer(object):
    def __init__(self, module_node):
        self.module_node = module_node
        self.collector = _Collector().collect(module_node)
        self.bindings = collections.OrderedDict()
        self.parser_configs = collections.OrderedDict()
        self.function_configs = collections.OrderedDict()
        self.decisions = []
        self._decision_keys = set()
        self._decisions_by_key = {}

        self._mark_fallbacks()
        self._build_bindings()
        self._build_function_configs()
        self._build_parser_configs()
        self._add_direct_fallback_decisions()
        self._analyze_calls()

    def _mark_fallbacks(self):
        body_imports = collections.defaultdict(list)
        handler_imports = collections.defaultdict(list)

        for occurrence in self.collector.imports:
            if occurrence.body_try is not None:
                body_imports[id(occurrence.body_try)].append(occurrence)
            if occurrence.handler_try is not None:
                handler_imports[id(occurrence.handler_try)].append(occurrence)

        for try_node in self.collector.tries:
            secure_imports = [
                occurrence for occurrence in body_imports[id(try_node)]
                if is_secure_factory_module(occurrence.module_path)
            ]
            fallback_imports = [
                occurrence for occurrence in handler_imports[id(try_node)]
                if is_insecure_factory_module(occurrence.module_path)
            ]

            if not secure_imports or not fallback_imports:
                continue

            for fallback in fallback_imports:
                matching = [
                    secure for secure in secure_imports
                    if secure.local_name == fallback.local_name
                    or (
                        _entry_point(secure.module_path)
                        and _entry_point(secure.module_path)
                        == _entry_point(fallback.module_path)
                    )
                ]
                fallback.fallback_main_path = (
                    matching[0].module_path
                    if matching
                    else secure_imports[0].module_path
                )

    def _build_bindings(self):
        for occurrence in self.collector.imports:
            binding = ImportBinding(
                occurrence.local_name,
                occurrence.module_path,
                occurrence.node,
                occurrence.function_depth,
                occurrence.fallback_main_path,
                (
                    occurrence.node
                    if occurrence.fallback_main_path is not None
                    else None
                ),
                occurrence.whole_path_import,
            )
            bindings = self.bindings.setdefault(occurrence.local_name, [])

            if any(
                existing.module_path == binding.module_path
                and existing.fallback_lineno == binding.fallback_lineno
                for existing in bindings
            ):
                continue

            bindings.append(binding)

    def _add_direct_fallback_decisions(self):
        for bindings in self.bindings.values():
            for binding in bindings:
                if not binding.is_fallback:
                    continue

                entry_point = _entry_point(binding.module_path)
                if (
                    entry_point is None
                    and is_insecure_factory_module(binding.module_path)
                ):
                    entry_points = ENTRY_POINTS
                elif entry_point is None:
                    continue
                else:
                    entry_points = (entry_point,)

                for current_entry_point in entry_points:
                    self._add_decision(
                        XMLParserDecision(
                            current_entry_point,
                            self._scope_for_import(binding),
                            False,
                            binding.fallback_lineno,
                            binding.fallback_col_offset,
                            module_path=binding.module_path,
                            fallback=True,
                            fallback_lineno=binding.fallback_lineno,
                            fallback_col_offset=binding.fallback_col_offset,
                            reason='insecure compatibility fallback',
                        )
                    )

    def _scope_for_import(self, binding):
        if binding.function_depth > 0:
            return PER_REQUEST
        return IMPORT_BUILD_TIME

    def _resolve_paths(self, function_node):
        path = tree.module_path_str(function_node)
        if not path:
            return []

        parts = path.split('.')
        bindings = self.bindings.get(parts[0], [])
        resolved = []

        for binding in bindings:
            if binding.module_path.endswith('.*'):
                continue

            resolved_path = binding.module_path
            if binding.whole_path_import:
                resolved_path = path
            elif len(parts) > 1:
                resolved_path += '.' + '.'.join(parts[1:])

            resolved.append((resolved_path, binding))

        if not resolved:
            if (
                _entry_point(path)
                or is_secure_factory_module(path)
                or is_insecure_factory_module(path)
            ):
                resolved.append((path, None))

        unique = collections.OrderedDict()
        for resolved_path, binding in resolved:
            key = (
                resolved_path,
                binding.fallback_lineno if binding is not None else None,
            )
            unique.setdefault(key, (resolved_path, binding))

        return list(unique.values())

    def _build_function_configs(self):
        for name, function_node in self.collector.function_nodes.items():
            secure, module_path = self._function_parser_security(function_node)
            if module_path is None and secure is None:
                continue
            self.function_configs[name] = (secure, module_path)

    def _function_parser_security(self, function_node):
        local_configs = collections.OrderedDict()
        results = []

        for node in ast.walk(function_node):
            if isinstance(node, ast.Assign):
                if (
                    len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                ):
                    secure, module_path = self._parser_factory_security(
                        node.value
                    )
                    if module_path is not None or secure is not None:
                        local_configs[node.targets[0].id] = (
                            secure,
                            module_path,
                        )

            elif isinstance(node, ast.Return) and node.value is not None:
                if isinstance(node.value, ast.Name):
                    result = local_configs.get(node.value.id)
                else:
                    result = self._parser_factory_security(node.value)

                if result is not None and (
                    result[0] is not None or result[1] is not None
                ):
                    results.append(result)

        if not results:
            return None, None

        first_path = next(
            (module_path for _secure, module_path in results
             if module_path is not None),
            None,
        )
        return _combine_security([secure for secure, _path in results]), first_path

    def _build_parser_configs(self):
        for assignment in self.collector.assignments:
            if isinstance(assignment.value, ast.Name):
                existing = self.parser_configs.get(assignment.value.id)
                if existing is not None:
                    secure = existing.secure
                    module_path = existing.module_path
                else:
                    factory = self.function_configs.get(assignment.value.id)
                    if factory is None:
                        continue
                    secure, module_path = factory
            else:
                secure, module_path = self._parser_factory_security(
                    assignment.value
                )
                if (
                    module_path is None
                    and secure is None
                    and isinstance(assignment.value, ast.Call)
                ):
                    factory_name = tree.module_path_str(
                        assignment.value.func
                    )
                    factory = self.function_configs.get(factory_name)
                    if factory is not None:
                        secure, module_path = factory

            if module_path is None and secure is None:
                continue

            scope = (
                PER_REQUEST
                if assignment.function_depth > 0
                else IMPORT_BUILD_TIME
            )
            config = ParserConfig(
                assignment.name,
                secure,
                scope,
                assignment.node,
                module_path,
            )

            existing = self.parser_configs.get(assignment.name)
            if existing is not None and (
                existing.secure != config.secure
                or existing.scope != config.scope
            ):
                self.parser_configs[assignment.name] = ParserConfig(
                    assignment.name,
                    None,
                    UNKNOWN,
                    assignment.node,
                    module_path,
                )
            else:
                self.parser_configs[assignment.name] = config

    def _parser_factory_security(self, node):
        if not isinstance(node, ast.Call):
            return None, None

        paths = self._resolve_paths(node.func)
        if not paths:
            return None, None

        security = []
        for module_path, _binding in paths:
            if module_path.rsplit('.', 1)[-1] not in _PARSER_CLASS_NAMES:
                return None, None

            if is_secure_factory_module(module_path):
                security.append(_defusedxml_call_secure(node))
            elif module_path.startswith('lxml.etree.'):
                security.append(_lxml_parser_secure(node))
            elif is_insecure_factory_module(module_path):
                security.append(False)
            else:
                security.append(None)

        return _combine_security(security), paths[0][0]

    def _parser_argument_security(self, call, function_depth):
        parser_value = _kwarg_value(call, 'parser')
        if parser_value is _MISSING:
            return _MISSING

        if isinstance(parser_value, ast.Name):
            config = self.parser_configs.get(parser_value.id)
            if config is None:
                return None, UNKNOWN
            return config.secure, config.scope

        if isinstance(parser_value, ast.Call):
            secure, module_path = self._parser_factory_security(parser_value)
            if module_path is None and secure is None:
                factory_name = tree.module_path_str(parser_value.func)
                factory = self.function_configs.get(factory_name)
                if factory is not None:
                    secure, module_path = factory

            scope = (
                PER_REQUEST
                if function_depth > 0
                else IMPORT_BUILD_TIME
            )
            return secure, scope

        return None, UNKNOWN

    def _call_security(self, call, paths, function_depth):
        parser_security = self._parser_argument_security(call, function_depth)
        parser_scope = (
            parser_security[1]
            if parser_security is not _MISSING
            else None
        )
        securities = []

        for module_path, _binding in paths:
            if is_secure_factory_module(module_path):
                secure = _defusedxml_call_secure(call)
                if secure is not True and parser_security is not _MISSING:
                    secure = parser_security[0]
                securities.append(secure)
            elif is_insecure_factory_module(module_path):
                if (
                    module_path.startswith('lxml.etree.')
                    and parser_security is not _MISSING
                    and parser_security[0] is True
                ):
                    securities.append(True)
                else:
                    securities.append(False)
            else:
                securities.append(None)

        return _combine_security(securities), parser_scope

    def _analyze_calls(self):
        for occurrence in self.collector.calls:
            call = occurrence.node
            paths = self._resolve_paths(call.func)
            if not paths:
                continue

            entry_paths = []
            for module_path, binding in paths:
                if _entry_point(module_path) is None:
                    continue

                if (
                    is_secure_factory_module(module_path)
                    or is_insecure_factory_module(module_path)
                ):
                    entry_paths.append((module_path, binding))
                elif (
                    binding is None
                    and "." not in module_path
                    and module_path not in self.collector.function_names
                ):
                    entry_paths.append((module_path, binding))

            if not entry_paths:
                continue

            paths = entry_paths
            entry_point = _entry_point(paths[0][0])

            secure, parser_scope = self._call_security(
                call,
                paths,
                occurrence.function_depth,
            )
            fallback_binding = next(
                (
                    binding for module_path, binding in paths
                    if binding is not None
                    and binding.is_fallback
                    and is_insecure_factory_module(module_path)
                ),
                None,
            )

            if fallback_binding is not None:
                module_path = next(
                    module_path for module_path, binding in paths
                    if binding is fallback_binding
                )
                self._add_decision(
                    XMLParserDecision(
                        entry_point,
                        self._scope_for_import(fallback_binding),
                        secure,
                        fallback_binding.fallback_lineno,
                        fallback_binding.fallback_col_offset,
                        module_path=module_path,
                        fallback=True,
                        fallback_lineno=fallback_binding.fallback_lineno,
                        fallback_col_offset=fallback_binding.fallback_col_offset,
                        reason='insecure compatibility fallback',
                        call_lineno=call.lineno,
                        call_col_offset=call.col_offset,
                    )
                )
                continue

            if secure is None:
                scope = UNKNOWN
            elif parser_scope is not None:
                scope = parser_scope
            else:
                scope = (
                    PER_REQUEST
                    if occurrence.function_depth > 0
                    else IMPORT_BUILD_TIME
                )

            self._add_decision(
                XMLParserDecision(
                    entry_point,
                    scope,
                    secure,
                    call.lineno,
                    call.col_offset,
                    module_path=paths[0][0],
                    fallback=False,
                    reason=(
                        'explicit parser configuration'
                        if secure is not None
                        else 'dynamic or unresolved parser configuration'
                    ),
                    call_lineno=call.lineno,
                    call_col_offset=call.col_offset,
                )
            )

    def _add_decision(self, decision):
        key = (
            decision.entry_point,
            decision.scope,
            decision.secure,
            decision.lineno,
            decision.col_offset,
            decision.fallback_lineno,
            decision.fallback_col_offset,
        )
        if key in self._decision_keys:
            existing = self._decisions_by_key[key]
            if existing.call_lineno is None:
                existing.call_lineno = decision.call_lineno
            if existing.call_col_offset is None:
                existing.call_col_offset = decision.call_col_offset
            return

        self._decision_keys.add(key)
        self._decisions_by_key[key] = decision
        self.decisions.append(decision)


def _combine_security(securities):
    if not securities:
        return None
    if any(security is False for security in securities):
        return False
    if any(security is None for security in securities):
        return None
    return True


def summarize_xml_parser_decisions(module_node):
    if isinstance(module_node, str):
        module_node = ast.parse(module_node)
    return XMLParserSummary(_Analyzer(module_node).decisions)


def audit_xml_parser_decisions(module_node):
    return summarize_xml_parser_decisions(module_node)


# Convenience aliases for callers that use shorter names.
Decision = XMLParserDecision
Summary = XMLParserSummary
summarize = summarize_xml_parser_decisions
audit = audit_xml_parser_decisions
summarize_module = summarize_xml_parser_decisions
