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


FactoryFinding = collections.namedtuple(
    'FactoryFinding',
    ['section', 'name', 'kind', 'value', 'status', 'lineno', 'col_offset']
)


class UnresolvedValue(object):
    """Sentinel for configuration values that cannot be resolved without
    executing the analyzed module. Carries the AST node that defeated
    resolution so it can be reported separately.
    """

    def __init__(self, node):
        self.node = node


class BadLoggingConfigUseLinter(base.BaseLinter):
    """This linter inspects dictionaries passed to
    ``logging.config.dictConfig`` and identifies the factory strings Python
    will parse or call when the configuration is applied:

    * ``handlers.<name>["class"]``
    * ``formatters.<name>["()"]``
    * ``filters.<name>["()"]``

    Only the single module containing the ``dictConfig`` call is analyzed.
    Local literal dictionaries, explicit merges (``**other`` and
    ``dict(a, **b)``) and a bounded number of module-scope or local constant
    references are understood. Values that cannot be resolved statically are
    reported with an ``unresolved`` status rather than guessed at. The
    analyzed module is never imported or executed.

    Callers may declare reviewed factories through
    ``approved_factories``; subclasses (including Dlint plugins) can extend
    the tuple to pre-approve additional dotted paths.
    """
    off_by_default = False

    _code = 'DUO139'
    _error_tmpl = 'DUO139 logging.config.dictConfig factory "{value}" requires review ({path})'
    _unresolved_tmpl = 'DUO139 logging.config.dictConfig factory at {path} cannot be resolved statically'
    _config_unresolved_tmpl = 'DUO139 logging.config.dictConfig argument cannot be resolved statically'

    # Dotted paths that resolve to factories shipped with the standard
    # library. Anything else (third-party or project-local callables) must be
    # reviewed before deployment and may be declared via a subclass.
    approved_factories = (
        'logging.Formatter',
        'logging.Filter',
    )

    # Constant references are only followed this many times to keep analysis
    # cheap and to break accidental assignment cycles.
    max_resolution_depth = 8

    _factory_slots = (
        ('handlers', 'class'),
        ('formatters', '()'),
        ('filters', '()'),
    )

    def __init__(self, *args, **kwargs):
        # name -> list of assigned value nodes, innermost assignment last.
        # Only plain name targets are tracked.
        self._assignments = collections.defaultdict(list)
        self._resolution_stack = set()
        self._findings = []

        super(BadLoggingConfigUseLinter, self).__init__(*args, **kwargs)

    @property
    def factory_findings(self):
        """Structured report of every enabled factory slot.

        Returns ``FactoryFinding`` namedtuples whose ``status`` is one of
        ``review`` (dotted path not in ``approved_factories``),
        ``approved`` (dotted path in ``approved_factories``) or
        ``unresolved`` (dynamic value that could not be analyzed).
        """
        return list(self._findings)

    def get_approval_list(self):
        """Deduplicated dotted paths reviewers must sign off on.

        Strings used in ordinary description positions are never collected:
        only values found at a factory slot enter the list.
        """
        seen = set()
        result = []

        for finding in self._findings:
            if finding.status != 'review':
                continue
            if finding.value in seen:
                continue
            seen.add(finding.value)
            result.append(finding.value)

        return result

    def get_results(self):
        """Flake8-compatible output.

        Approved factories produce no findings so existing plugin consumers
        keep working; review and unresolved entries are emitted as ordinary
        ``Flake8Result`` objects.
        """
        results = []

        for finding in self._findings:
            if finding.status == 'approved':
                continue

            if not finding.section:
                message = self._config_unresolved_tmpl
            else:
                path = '{}.{}.{}'.format(
                    finding.section, finding.name, finding.kind
                )

                if finding.status == 'unresolved':
                    message = self._unresolved_tmpl.format(path=path)
                else:
                    message = self._error_tmpl.format(
                        value=finding.value,
                        path=path
                    )

            results.append(
                base.Flake8Result(
                    lineno=finding.lineno,
                    col_offset=finding.col_offset,
                    message=message
                )
            )

        return results

    def visit_Assign(self, node):
        self.generic_visit(node)

        for target in node.targets:
            if isinstance(target, ast.Name):
                self._assignments[target.id].append(node.value)

    def visit_Call(self, node):
        self.generic_visit(node)

        if not self._is_dictconfig_call(node):
            return

        config_node = self._call_config_node(node)
        if config_node is None:
            return

        config = self._resolve_mapping(config_node, depth=0)

        if isinstance(config, UnresolvedValue):
            self._findings.append(
                FactoryFinding(
                    section='',
                    name='',
                    kind='',
                    value=None,
                    status='unresolved',
                    lineno=config.node.lineno,
                    col_offset=config.node.col_offset
                )
            )
            return

        self._collect_factories(config)

    def _is_dictconfig_call(self, node):
        func = node.func

        if isinstance(func, ast.Attribute) and func.attr == 'dictConfig':
            # E.g. logging.config.dictConfig(...) or an aliased import.
            return self.namespace.illegal_module_imported(
                tree.module_path_str(func.value),
                'logging.config'
            )

        if isinstance(func, ast.Name):
            # 'from logging.config import dictConfig' (optionally aliased).
            # The same name could be imported from an unrelated module, so
            # both the binding and its origin must match.
            imported_name = self.namespace.asname_to_name(func.id) or func.id
            if imported_name != 'dictConfig':
                return False

            return self.namespace.illegal_module_imported(
                'logging.config.dictConfig',
                'logging.config.dictConfig'
            )

        return False

    @staticmethod
    def _call_config_node(call):
        for keyword in call.keywords:
            if keyword.arg == 'config':
                return keyword.value

        if call.args:
            return call.args[0]

        return None

    def _collect_factories(self, config):
        for section, slot in self._factory_slots:
            section_node = self._mapping_get(config, section)
            if section_node is None:
                continue

            section_map = self._resolve_mapping(section_node, depth=0)
            if isinstance(section_map, UnresolvedValue):
                continue

            for name_node, entry_node in self._mapping_items(section_map):
                if not isinstance(name_node, ast.Str):
                    continue

                entry = self._resolve_mapping(entry_node, depth=0)
                if not isinstance(entry, ast.Dict):
                    continue

                factory = self._mapping_get(entry, slot)
                if factory is None:
                    continue

                factory = self._dereference(factory, depth=0)
                self._record_finding(section, name_node.s, slot, factory)

    def _record_finding(self, section, name, slot, node):
        if isinstance(node, UnresolvedValue):
            self._findings.append(
                FactoryFinding(
                    section=section,
                    name=name,
                    kind=slot,
                    value=None,
                    status='unresolved',
                    lineno=node.node.lineno,
                    col_offset=node.node.col_offset
                )
            )
            return

        if not isinstance(node, ast.Str):
            # E.g. an actual class object instead of a dotted string.
            self._findings.append(
                FactoryFinding(
                    section=section,
                    name=name,
                    kind=slot,
                    value=None,
                    status='unresolved',
                    lineno=node.lineno,
                    col_offset=node.col_offset
                )
            )
            return

        value = node.s
        status = (
            'approved'
            if value in self.approved_factories
            else 'review'
        )

        self._findings.append(
            FactoryFinding(
                section=section,
                name=name,
                kind=slot,
                value=value,
                status=status,
                lineno=node.lineno,
                col_offset=node.col_offset
            )
        )

    # -- Static resolution -------------------------------------------------

    def _resolve_mapping(self, node, depth):
        """Resolve an expression to a mapping of key-node -> value-node.

        Returns an ``ast.Dict`` representing the merged mapping, or
        ``UnresolvedValue`` when the expression cannot be understood. Merge
        ordering follows Python semantics: later sources override earlier
        ones, so risk lands on the path that is actually enabled.
        """
        node = self._dereference(node, depth)

        if isinstance(node, UnresolvedValue):
            return node

        if isinstance(node, ast.Dict):
            return self._flatten_dict(node, depth)

        if isinstance(node, ast.Call) and self._is_dict_constructor(node):
            return self._flatten_dict_constructor(node, depth)

        return UnresolvedValue(node)

    def _flatten_dict(self, node, depth):
        keys = []
        values = []

        for key, value in zip(node.keys, node.values):
            if key is None:
                # '**other' explicit merge.
                merged = self._resolve_mapping(value, depth + 1)
                if isinstance(merged, UnresolvedValue):
                    return merged

                for inner_key, inner_value in zip(merged.keys, merged.values):
                    self._merge_pair(keys, values, inner_key, inner_value)
            else:
                self._merge_pair(keys, values, key, value)

        return ast.Dict(keys=keys, values=values)

    def _flatten_dict_constructor(self, node, depth):
        keys = []
        values = []

        for arg in node.args:
            merged = self._resolve_mapping(arg, depth + 1)
            if isinstance(merged, UnresolvedValue):
                return merged

            for inner_key, inner_value in zip(merged.keys, merged.values):
                self._merge_pair(keys, values, inner_key, inner_value)

        for keyword in node.keywords:
            if keyword.arg is None:
                merged = self._resolve_mapping(keyword.value, depth + 1)
                if isinstance(merged, UnresolvedValue):
                    return merged

                for inner_key, inner_value in zip(merged.keys, merged.values):
                    self._merge_pair(keys, values, inner_key, inner_value)
            else:
                self._merge_pair(
                    keys,
                    values,
                    ast.Str(s=keyword.arg),
                    keyword.value
                )

        return ast.Dict(keys=keys, values=values)

    @staticmethod
    def _merge_pair(keys, values, key, value):
        for index, existing_key in enumerate(keys):
            if isinstance(existing_key, ast.Str) and isinstance(key, ast.Str) \
                    and existing_key.s == key.s:
                values[index] = value
                return

        keys.append(key)
        values.append(value)

    @staticmethod
    def _is_dict_constructor(node):
        func = node.func
        return isinstance(func, ast.Name) and func.id == 'dict'

    def _dereference(self, node, depth):
        """Follow a bounded chain of plain-name constant references."""
        if depth >= self.max_resolution_depth:
            return UnresolvedValue(node)

        if not isinstance(node, ast.Name):
            return node

        if node.id in self._resolution_stack:
            return UnresolvedValue(node)

        assignments = self._assignments.get(node.id)
        if not assignments:
            return UnresolvedValue(node)

        target = assignments[-1]

        self._resolution_stack.add(node.id)
        try:
            if isinstance(target, ast.Name):
                return self._dereference(target, depth + 1)
            return target
        finally:
            self._resolution_stack.discard(node.id)

    @staticmethod
    def _mapping_get(mapping, key):
        for existing_key, value in zip(mapping.keys, mapping.values):
            if isinstance(existing_key, ast.Str) and existing_key.s == key:
                return value

        return None

    @staticmethod
    def _mapping_items(mapping):
        return list(zip(mapping.keys, mapping.values))
