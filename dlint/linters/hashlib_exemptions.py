#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast
import copy
import datetime
import hashlib
import os
import sys

from . import base


EXEMPTION_VARIABLE_NAME = 'DLINT_DUO130_EXEMPTIONS'
FILE_BUCKETING_PURPOSE = 'file_bucketing'
SUPPORTED_CHECK_CODE = 'DUO130'
AUDIT_ERROR_TEMPLATE = 'DUO130 invalid static exemption: {}'
REQUIRED_FIELDS = frozenset((
    'approval_id',
    'check_code',
    'filename',
    'function_fingerprint',
    'function_end_line',
    'function_start_line',
    'lineno',
    'col_offset',
    'purpose',
    'qualified_name',
    'valid_until',
))


class HashlibExemption(object):
    def __init__(self, values):
        values = dict(values)
        missing_fields = REQUIRED_FIELDS - frozenset(values)
        unknown_fields = frozenset(values) - REQUIRED_FIELDS

        if missing_fields or unknown_fields:
            raise ValueError('invalid DUO130 exemption fields')

        self.approval_id = values['approval_id']
        self.check_code = values['check_code']
        self.filename = values['filename']
        self.function_fingerprint = values['function_fingerprint']
        self.function_end_line = values['function_end_line']
        self.function_start_line = values['function_start_line']
        self.lineno = values['lineno']
        self.col_offset = values['col_offset']
        self.purpose = values['purpose']
        self.qualified_name = values['qualified_name']
        self.valid_until = values['valid_until']

        self._validate()

    def _validate(self):
        if self.check_code != SUPPORTED_CHECK_CODE:
            raise ValueError('DUO130 exemptions may only suppress DUO130')

        if self.purpose != FILE_BUCKETING_PURPOSE:
            raise ValueError('DUO130 exemptions are limited to file bucketing')

        self._validate_date()

        integer_fields = (
            'col_offset',
            'function_end_line',
            'function_start_line',
            'lineno',
        )
        for field_name in integer_fields:
            field_value = getattr(self, field_name)
            if (
                not isinstance(field_value, int)
                or isinstance(field_value, bool)
                or field_value < 1
            ):
                raise ValueError('DUO130 exemption line and column fields must be integers')

        string_fields = ('filename', 'qualified_name')
        for field_name in string_fields:
            if not isinstance(getattr(self, field_name), str) or not getattr(self, field_name):
                raise ValueError('DUO130 exemption filename and scope must be non-empty strings')

        for field_name in ('approval_id', 'function_fingerprint'):
            field_value = getattr(self, field_name)
            if not isinstance(field_value, str) or not field_value:
                raise ValueError('DUO130 exemption {} must be a non-empty string'.format(field_name))

        if os.path.isabs(self.filename) or os.path.normpath(self.filename).startswith('..'):
            raise ValueError('DUO130 exemption filename must be a repository-relative path')

        if not (self.function_start_line <= self.lineno <= self.function_end_line):
            raise ValueError('DUO130 exemption result must be inside its approved function range')

    def _validate_date(self):
        if not isinstance(self.valid_until, str):
            raise ValueError('DUO130 exemption valid_until must be an ISO date string')

        try:
            self.expiration_date = datetime.datetime.strptime(
                self.valid_until,
                '%Y-%m-%d'
            ).date()
        except ValueError:
            raise ValueError('DUO130 exemption valid_until must use YYYY-MM-DD')

    def is_active(self, today):
        return today <= self.expiration_date

    def matches_result(self, result, function_scope, filename):
        return (
            result.message.startswith(self.check_code + ' ')
            and self.lineno == result.lineno
            and self.col_offset == result.col_offset
            and self._matches_filename(filename)
            and self._matches_function_scope(function_scope)
        )

    def _matches_filename(self, filename):
        if not filename:
            return False

        normalized_filename = os.path.normpath(filename).replace(os.sep, '/')
        normalized_exemption_filename = os.path.normpath(self.filename).replace(os.sep, '/')
        return (
            normalized_filename == normalized_exemption_filename
            or normalized_filename.endswith('/' + normalized_exemption_filename)
        )

    def _matches_function_scope(self, function_scope):
        if not function_scope:
            return False

        return (
            function_scope.qualified_name == self.qualified_name
            and function_scope.start_line == self.function_start_line
            and function_scope.end_line == self.function_end_line
            and function_scope.fingerprint == self.function_fingerprint
        )


class FunctionScope(object):
    def __init__(self, qualified_name, start_line, end_line, fingerprint):
        self.qualified_name = qualified_name
        self.start_line = start_line
        self.end_line = end_line
        self.fingerprint = fingerprint


def parse_exemptions(module_node):
    assignment_nodes = [
        node for node in module_node.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name)
            and target.id == EXEMPTION_VARIABLE_NAME
            for target in node.targets
        )
    ]

    if not assignment_nodes:
        return []

    if len(assignment_nodes) != 1:
        raise ValueError('duplicate DUO130 exemption declarations')

    values = _literal_values(assignment_nodes[0].value)
    if not isinstance(values, (list, tuple)):
        raise ValueError('DUO130 exemptions must be a list or tuple')

    exemptions = []
    exemption_keys = set()
    approval_ids = set()
    for value in values:
        if not isinstance(value, dict):
            raise ValueError('each DUO130 exemption must be a dictionary')

        exemption = HashlibExemption(value)

        exemption_key = (
            exemption.filename,
            exemption.qualified_name,
            exemption.lineno,
            exemption.col_offset,
        )
        if exemption_key in exemption_keys:
            raise ValueError('duplicate DUO130 exemption entries are not permitted')

        if exemption.approval_id in approval_ids:
            raise ValueError('duplicate DUO130 approval identifiers are not permitted')

        exemption_keys.add(exemption_key)
        approval_ids.add(exemption.approval_id)
        exemptions.append(exemption)

    return exemptions


def get_function_scope(module_node, result):
    scopes = []

    class FunctionScopeVisitor(ast.NodeVisitor):
        def __init__(self):
            self.class_names = []
            self.function_names = []

        def visit_ClassDef(self, node):
            self.class_names.append(node.name)
            self.generic_visit(node)
            self.class_names.pop()

        def visit_FunctionDef(self, node):
            self._visit_function(node)

        def visit_AsyncFunctionDef(self, node):
            self._visit_function(node)

        def _visit_function(self, node):
            self.function_names.append(node.name)
            if node.lineno <= result.lineno <= node_end_line(node):
                scopes.append(self._scope(node))

            self.generic_visit(node)
            self.function_names.pop()

        def _scope(self, node):
            qualified_parts = self.class_names + list(self.function_names)
            return FunctionScope(
                '.'.join(qualified_parts),
                node.lineno,
                node_end_line(node),
                fingerprint_function(node)
            )

    FunctionScopeVisitor().visit(module_node)

    if not scopes:
        return None

    return sorted(scopes, key=lambda scope: (scope.end_line, scope.start_line))[0]


def filter_results(results, module_node, filename, today=None):
    today = today or datetime.date.today()
    try:
        exemptions = parse_exemptions(module_node)
    except ValueError as exc:
        return results + [_audit_result(str(exc))]

    active_exemptions = [
        exemption for exemption in exemptions
        if exemption.is_active(today)
    ]

    filtered_results = []
    matched_exemptions = set()
    for result in results:
        function_scope = get_function_scope(module_node, result)
        for index, exemption in enumerate(active_exemptions):
            if exemption.matches_result(result, function_scope, filename):
                matched_exemptions.add(index)
                break
        else:
            filtered_results.append(result)

    unmatched_exemptions = [
        exemption for index, exemption in enumerate(active_exemptions)
        if index not in matched_exemptions
    ]
    if unmatched_exemptions:
        return results + [
            _audit_result('exemption does not match a current check result')
        ]

    return filtered_results


def _audit_result(message):
    return base.Flake8Result(
        lineno=1,
        col_offset=0,
        message=AUDIT_ERROR_TEMPLATE.format(message)
    )


def node_end_line(node):
    end_line = getattr(node, 'end_lineno', None)
    if end_line is not None:
        return end_line

    end_line = node.lineno
    for child in ast.walk(node):
        child_end_line = getattr(child, 'lineno', end_line)
        if child_end_line > end_line:
            end_line = child_end_line
    return end_line


def fingerprint_function(node):
    structural_node = _strip_location_fields(copy.deepcopy(node))
    structural_dump = _dump_node(structural_node)
    return hashlib.sha256(structural_dump.encode('utf-8')).hexdigest()


def _strip_location_fields(node):
    for attribute_name in ('lineno', 'col_offset', 'end_lineno', 'end_col_offset'):
        if hasattr(node, attribute_name):
            delattr(node, attribute_name)

    for child_node in ast.iter_child_nodes(node):
        if not isinstance(child_node, ast.AST):
            continue
        _strip_location_fields(child_node)

    return node


def _dump_node(node):
    if not isinstance(node, ast.AST):
        return repr(node)

    parts = [node.__class__.__name__]
    for field_name in node._fields:
        if not hasattr(node, field_name):
            continue

        value = getattr(node, field_name)
        if isinstance(value, list):
            dumped_items = [
                _dump_node(item) for item in value
                if isinstance(item, ast.AST)
            ]
            dumped_value = '[' + ', '.join(dumped_items) + ']'
        else:
            if value is not None and not isinstance(value, ast.AST):
                dumped_value = repr(value)
            else:
                dumped_value = _dump_node(value)
        parts.append(field_name + '=' + dumped_value)

    return '{}({})'.format(parts[0], ', '.join(parts[1:]))


def _literal_values(node):
    if sys.version_info >= (3, 8) and isinstance(node, ast.Constant):
        return node.value
    if sys.version_info < (3, 8) and hasattr(ast, 'Str') and isinstance(node, ast.Str):
        return node.s
    if sys.version_info < (3, 8) and hasattr(ast, 'Num') and isinstance(node, ast.Num):
        return node.n
    if (
        sys.version_info < (3, 8)
        and hasattr(ast, 'NameConstant')
        and isinstance(node, ast.NameConstant)
    ):
        return node.value
    if isinstance(node, ast.List):
        return [_literal_values(child) for child in node.elts]
    if isinstance(node, ast.Tuple):
        return tuple(_literal_values(child) for child in node.elts)
    if isinstance(node, ast.Dict):
        return {
            _literal_values(key): _literal_values(value)
            for key, value in zip(node.keys, node.values)
        }

    raise ValueError('DUO130 exemption values must be static literals')
