#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast
import collections
import io
import re
import tokenize


# Each entry maps a version-sensitive syntax feature to the interpreter
# version that first parses it. Detection is purely static so the audit can
# reason about interpreters other than the one running this code.
_FEATURE_INTRODUCED = collections.OrderedDict([
    ('nonlocal_keyword', (3, 0)),
    ('async_function', (3, 5)),
    ('async_await_keyword', (3, 5)),
    ('starred_unpacking', (3, 5)),
    ('f_string', (3, 6)),
    ('variable_annotations', (3, 6)),
    ('async_generator', (3, 6)),
    ('async_comprehension', (3, 6)),
    ('walrus_operator', (3, 8)),
    ('positional_only_parameters', (3, 8)),
    ('debug_f_string', (3, 8)),
    ('match_statement', (3, 10)),
    ('parenthesized_context_managers', (3, 10)),
    ('exception_groups', (3, 11)),
    ('type_alias_statement', (3, 12)),
])

# Python 2-only grammar that a Python 3 parser cannot build an AST from.
# These have to be detected from the raw source text. Each feature was
# removed starting at the listed interpreter version, so a target
# environment supports it only when its version is below that point.
_PY2_ONLY_REMOVED = collections.OrderedDict([
    ('print_statement', (3, 0)),
    ('exec_statement', (3, 0)),
    ('backtick_repr', (3, 0)),
    ('inequality_alias', (3, 0)),
])

_PRINT_STATEMENT_RE = re.compile(
    r'''^[ \t]*print(?:[ \t]*>>|[ \t]+(?:[^(\n]|$))'''
)
_EXEC_STATEMENT_RE = re.compile(
    r'''^[ \t]*exec[ \t]+(?!=)'''
)
_BACKTICK_RE = re.compile(r'`[^`\n]+`')
_NAMED_EXPR_RE = re.compile(r':=')
_TYPE_ALIAS_RE = re.compile(r'^[ \t]*type[ \t]+[A-Za-z_]\w*[ \t]*=')
_EXCEPT_STAR_RE = re.compile(r'^[ \t]*except\*(?:[ \t]|:)')
_DEBUG_FSTRING_RE = re.compile(r'''[fF][rR]?['"]\{.*?=\s*[!}].*?\}''')


def normalize_version(version):
    """Normalize a version into a ``(major, minor)`` tuple of integers."""
    if isinstance(version, int):
        return (version, 0)

    if isinstance(version, tuple):
        return (int(version[0]), int(version[1]))

    parts = str(version).split('.')
    return (int(parts[0]), int(parts[1] if len(parts) > 1 else 0))


def _supports(version, introduced):
    return normalize_version(version) >= normalize_version(introduced)


def _tokens(source):
    try:
        return list(tokenize.generate_tokens(io.StringIO(source).readline))
    except tokenize.TokenError:
        return []


def _line_offsets(source):
    offsets = [0]
    for char in source:
        if char == '\n':
            offsets.append(offsets[-1] + 1)
    return offsets


def _line_col(source, position):
    offsets = _line_offsets(source)
    line = 1
    for index, offset in enumerate(offsets):
        if offset > position:
            break
        line = index + 1
    line_start = offsets[line - 1]
    return line, position - line_start


def _detect_python2_only(source):
    features = []

    for index, line in enumerate(source.splitlines(), start=1):
        stripped = line.lstrip()
        if stripped.startswith('#'):
            continue

        if _PRINT_STATEMENT_RE.match(line):
            features.append(('print_statement', index, 0))
        if _EXEC_STATEMENT_RE.match(line):
            features.append(('exec_statement', index, len(line) - len(line.lstrip())))
        if any(
            token.type == tokenize.OP and token.string == '<>'
            for token in _tokens(line)
        ):
            features.append(('inequality_alias', index, line.find('<>')))

    for match in _BACKTICK_RE.finditer(source):
        lineno, col = _line_col(source, match.start())
        features.append(('backtick_repr', lineno, col))

    return features


def _node_uses_async_function(node):
    for inner in ast.walk(node):
        if isinstance(inner, ast.AsyncFunctionDef):
            return inner
    return None


def _node_uses_await(node):
    for inner in ast.walk(node):
        if isinstance(inner, ast.Await):
            return inner
    return None


def _node_uses_async_comprehension(node):
    for inner in ast.walk(node):
        if isinstance(inner, ast.comprehension) and getattr(inner, 'is_async', 0):
            return inner
    return None


def _node_uses_async_generator(node):
    async_def = getattr(ast, 'AsyncFunctionDef', None)
    if async_def is None:
        return None

    for inner in ast.walk(node):
        if isinstance(inner, async_def) and any(
            isinstance(descendant, (ast.Yield, ast.YieldFrom))
            for descendant in ast.walk(inner)
        ):
            return inner
    return None


def _node_uses_variable_annotations(node):
    for inner in ast.walk(node):
        if isinstance(inner, getattr(ast, 'AnnAssign', ())):
            return inner
        if isinstance(inner, ast.arg) and getattr(inner, 'annotation', None):
            return inner
    return None


def _node_uses_f_strings(node):
    joined_str = getattr(ast, 'JoinedStr', None)
    if joined_str is None:
        return None
    for inner in ast.walk(node):
        if isinstance(inner, joined_str):
            return inner
    return None


def _node_uses_nonlocal(node):
    nonlocal_node = getattr(ast, 'Nonlocal', None)
    if nonlocal_node is None:
        return None
    for inner in ast.walk(node):
        if isinstance(inner, nonlocal_node):
            return inner
    return None


def _node_uses_starred_unpacking(node):
    for inner in ast.walk(node):
        if isinstance(inner, ast.Starred) and isinstance(inner.ctx, ast.Load):
            return inner
    return None


def _node_uses_walrus(node):
    named_expr = getattr(ast, 'NamedExpr', None)
    if named_expr is None:
        return None
    for inner in ast.walk(node):
        if isinstance(inner, named_expr):
            return inner
    return None


def _node_uses_positional_only(node):
    for inner in ast.walk(node):
        arguments = getattr(inner, 'args', None)
        if arguments is not None and getattr(arguments, 'posonlyargs', None):
            return arguments.posonlyargs[0]
    return None


def _node_uses_match(node):
    match_stmt = getattr(ast, 'Match', None)
    if match_stmt is None:
        return None
    for inner in ast.walk(node):
        if isinstance(inner, match_stmt):
            return inner
    return None


def _node_uses_parenthesized_with(node):
    for inner in ast.walk(node):
        if isinstance(inner, ast.With) and len(inner.items) > 1:
            return inner
    return None


def detect_features(source, tree=None):
    """Return ``(features, parse_error)`` for the given source text.

    ``features`` is a tuple of ``(name, lineno, col_offset)`` triples. Python
    2-only syntax is detected from the raw text because the running Python 3
    interpreter cannot parse it into an AST.
    """
    features = list(_detect_python2_only(source))

    parse_error = None
    if tree is None:
        try:
            tree = ast.parse(source)
        except SyntaxError as error:
            parse_error = error
            tree = None

    if tree is not None:
        node_checks = (
            ('nonlocal_keyword', _node_uses_nonlocal),
            ('starred_unpacking', _node_uses_starred_unpacking),
            ('async_function', _node_uses_async_function),
            ('async_await_keyword', _node_uses_await),
            ('async_comprehension', _node_uses_async_comprehension),
            ('async_generator', _node_uses_async_generator),
            ('variable_annotations', _node_uses_variable_annotations),
            ('f_string', _node_uses_f_strings),
            ('walrus_operator', _node_uses_walrus),
            ('positional_only_parameters', _node_uses_positional_only),
            ('match_statement', _node_uses_match),
            ('parenthesized_context_managers',
             _node_uses_parenthesized_with),
        )

        for name, check in node_checks:
            node = check(tree)
            if node:
                features.append((name, getattr(node, 'lineno', 1),
                                 getattr(node, 'col_offset', 0)))

        if any(name == 'f_string' for name, _, _ in features):
            for match in _DEBUG_FSTRING_RE.finditer(source):
                lineno, col = _line_col(source, match.start())
                features.append(('debug_f_string', lineno, col))

        if not any(name == 'walrus_operator' for name, _, _ in features):
            for match in _NAMED_EXPR_RE.finditer(source):
                lineno, col = _line_col(source, match.start())
                features.append(('walrus_operator', lineno, col))

        for match in _TYPE_ALIAS_RE.finditer(source):
            lineno, col = _line_col(source, match.start())
            features.append(('type_alias_statement', lineno, col))

        for index, line in enumerate(source.splitlines(), start=1):
            if _EXCEPT_STAR_RE.match(line):
                features.append(('exception_groups', index,
                                 len(line) - len(line.lstrip())))

    seen = set()
    unique = []
    for feature in features:
        if feature[0] in seen:
            continue
        seen.add(feature[0])
        unique.append(feature)

    return tuple(unique), parse_error


def unsupported_features(source, target_version):
    """Return feature tuples the target interpreter version cannot parse."""
    features, _ = detect_features(source)
    target = normalize_version(target_version)

    unsupported = []
    for name, lineno, col in features:
        if name in _PY2_ONLY_REMOVED:
            removed_in = _PY2_ONLY_REMOVED[name]
            if target >= normalize_version(removed_in):
                unsupported.append(
                    collections.OrderedDict([
                        ('name', name),
                        ('lineno', lineno),
                        ('col_offset', col),
                        ('removed_in', removed_in),
                    ])
                )
            continue

        introduced = _FEATURE_INTRODUCED.get(name)
        if introduced is None:
            continue

        if not _supports(target, introduced):
            unsupported.append(
                collections.OrderedDict([
                    ('name', name),
                    ('lineno', lineno),
                    ('col_offset', col),
                    ('min_version', introduced),
                ])
            )

    return tuple(unsupported)


def is_supported(source, target_version, tree=None):
    """Return ``(supported, unsupported_features)`` for the target version."""
    unsupported = unsupported_features(source, target_version)

    if unsupported:
        return False, unsupported

    return True, ()
