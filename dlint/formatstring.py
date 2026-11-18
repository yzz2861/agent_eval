#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast
import collections

try:
    string_types = basestring  # noqa: F821
except NameError:
    string_types = str

_Constant = getattr(ast, 'Constant', None)

_AnnAssign = getattr(ast, 'AnnAssign', None)

_function_def_types = tuple(
    t for t in (
        getattr(ast, 'FunctionDef', None),
        getattr(ast, 'AsyncFunctionDef', None),
    )
    if t is not None
)

MAX_RESOLUTION_DEPTH = 10

KIND_UNSAFE_ATTRIBUTE = 'unsafe_attribute'
KIND_UNKNOWN_FORMAT_STRING = 'unknown_format_string'
KIND_UNKNOWN_OBJECT = 'unknown_object'

Step = collections.namedtuple('Step', ['kind', 'value'])

Field = collections.namedtuple(
    'Field',
    ['root', 'path', 'conversion', 'spec_fields', 'raw']
)

Finding = collections.namedtuple(
    'Finding',
    ['kind', 'lineno', 'col_offset', 'field', 'object_name']
)

STEP_ATTRIBUTE = 'attribute'
STEP_INDEX = 'index'


class FormatStringParseError(Exception):
    """Raised when a format string cannot be parsed."""


def parse_format_string(format_string):
    """Parse a Python format string into a list of Field objects.

    Literal escapes ("{{" and "}}") are consumed, replacement fields are
    parsed along with their indexes, conversion flags, and format specs.
    Nested replacement fields (e.g. dynamic width "{:{width}}") are
    available on each field's "spec_fields" attribute. Automatic field
    numbering is resolved to explicit positional indexes.
    """
    if not isinstance(format_string, string_types):
        raise TypeError(
            'expected a string, received {}'.format(type(format_string))
        )

    fields = []
    state = {'auto_index': 0, 'numbering': None}
    _parse_fields(format_string, fields, state)

    return fields


def _parse_fields(format_string, fields, state):
    i = 0
    n = len(format_string)

    while i < n:
        char = format_string[i]

        if char == '{':
            if i + 1 < n and format_string[i + 1] == '{':
                i += 2  # Literal escape
                continue
            field, i = _parse_field(format_string, i, state)
            fields.append(field)
        elif char == '}':
            if i + 1 < n and format_string[i + 1] == '}':
                i += 2  # Literal escape
                continue
            raise FormatStringParseError(
                "single '}}' encountered in format string"
            )
        else:
            i += 1


def _parse_field(format_string, start, state):
    # format_string[start] == '{' and not a literal escape
    i = start + 1
    n = len(format_string)

    root_chars = []
    while i < n and format_string[i] not in '.[!:}':
        root_chars.append(format_string[i])
        i += 1
    root = ''.join(root_chars)

    path = []
    while i < n and format_string[i] in '.[':
        if format_string[i] == '.':
            i += 1
            name_chars = []
            while i < n and format_string[i] not in '.[!:}':
                name_chars.append(format_string[i])
                i += 1
            if not name_chars:
                raise FormatStringParseError(
                    'expected attribute name in replacement field'
                )
            path.append(Step(STEP_ATTRIBUTE, ''.join(name_chars)))
        else:
            i += 1
            index_chars = []
            while i < n and format_string[i] != ']':
                index_chars.append(format_string[i])
                i += 1
            if i >= n:
                raise FormatStringParseError(
                    "missing ']' in replacement field"
                )
            i += 1
            path.append(Step(STEP_INDEX, ''.join(index_chars)))

    if root == '':
        if state['numbering'] == 'manual':
            raise FormatStringParseError(
                'cannot switch from manual field specification '
                'to automatic field numbering'
            )
        state['numbering'] = 'auto'
        root = str(state['auto_index'])
        state['auto_index'] += 1
    elif root.isdigit():
        if state['numbering'] == 'auto':
            raise FormatStringParseError(
                'cannot switch from automatic field numbering '
                'to manual field specification'
            )
        state['numbering'] = 'manual'

    conversion = None
    if i < n and format_string[i] == '!':
        i += 1
        if i >= n or format_string[i] not in 'rsa':
            raise FormatStringParseError(
                'expected conversion flag "r", "s", or "a"'
            )
        conversion = format_string[i]
        i += 1

    spec_fields = []
    if i < n and format_string[i] == ':':
        i += 1
        spec_chars = []
        depth = 0
        closed = False
        while i < n:
            char = format_string[i]
            if char == '{':
                depth += 1
                spec_chars.append(char)
                i += 1
            elif char == '}':
                if depth == 0:
                    closed = True
                    break
                depth -= 1
                spec_chars.append(char)
                i += 1
            else:
                spec_chars.append(char)
                i += 1
        if not closed:
            raise FormatStringParseError("unmatched '{' in format string")
        _parse_fields(''.join(spec_chars), spec_fields, state)

    if i >= n or format_string[i] != '}':
        raise FormatStringParseError("unmatched '{' in format string")
    i += 1

    field = Field(
        root=root,
        path=tuple(path),
        conversion=conversion,
        spec_fields=spec_fields,
        raw=format_string[start:i]
    )

    return field, i


def check_source(source, capabilities=None):
    """Statically check Python source code for unsafe format string use.

    "capabilities" is a mapping of object names to collections of
    attribute names the format string is permitted to access, e.g.
    {"user": {"name", "email"}}. Returns a list of Finding objects.

    This function never imports, instantiates, or calls the objects it
    analyzes: the analysis is performed purely on the syntax tree.
    """
    return check_module(ast.parse(source), capabilities=capabilities)


def check_module(module_node, capabilities=None):
    """Statically check a module AST for unsafe format string use.

    See check_source for details.
    """
    normalized_capabilities = _normalize_capabilities(capabilities)
    facts = _ModuleFacts(module_node)

    findings = []

    for node in ast.walk(module_node):
        if not isinstance(node, ast.Call):
            continue

        call_info = _match_format_call(node)
        if call_info is None:
            continue

        format_expression, positional, keywords, mapping_mode = call_info

        format_string = facts.resolve_string(format_expression)
        if format_string is None:
            findings.append(
                Finding(
                    kind=KIND_UNKNOWN_FORMAT_STRING,
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    field=None,
                    object_name=None
                )
            )
            continue

        try:
            fields = parse_format_string(format_string)
        except FormatStringParseError:
            findings.append(
                Finding(
                    kind=KIND_UNKNOWN_FORMAT_STRING,
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                    field=None,
                    object_name=None
                )
            )
            continue

        findings.extend(
            _check_fields(
                fields,
                positional,
                keywords,
                mapping_mode,
                normalized_capabilities,
                node
            )
        )

    findings.sort(key=lambda finding: (finding.lineno, finding.col_offset))

    return findings


def _normalize_capabilities(capabilities):
    if capabilities is None:
        return {}

    return {
        name: frozenset(permitted_attributes)
        for name, permitted_attributes in capabilities.items()
    }


def _match_format_call(node):
    """Match "str.format" and "str.format_map" call sites.

    Returns (format_expression, positional_args, keyword_args,
    mapping_mode) or None when the call is not a format call.
    """
    if not isinstance(node.func, ast.Attribute):
        return None

    if node.func.attr == 'format':
        # Unbound form: str.format(format_string, *args, **kwargs)
        if isinstance(node.func.value, ast.Name) and node.func.value.id == 'str':
            if not node.args:
                return None
            return (node.args[0], node.args[1:], node.keywords, False)

        return (node.func.value, node.args, node.keywords, False)

    if node.func.attr == 'format_map':
        if not node.args:
            return None
        return (node.func.value, node.args[:1], [], True)

    return None


def _check_fields(fields, positional, keywords, mapping_mode, capabilities, call_node):
    findings = []

    for field in fields:
        target = _resolve_target(field, positional, keywords, mapping_mode)

        if target is not None:
            finding = _evaluate_target(target, field, capabilities, call_node)
            if finding is not None:
                findings.append(finding)

        findings.extend(
            _check_fields(
                field.spec_fields,
                positional,
                keywords,
                mapping_mode,
                capabilities,
                call_node
            )
        )

    return findings


def _resolve_target(field, positional, keywords, mapping_mode):
    if mapping_mode:
        # The field root is a key into the mapping; attribute and index
        # steps apply to the mapping's values, so the mapping itself is
        # the object whose capabilities matter.
        return positional[0]

    if field.root.isdigit():
        index = int(field.root)
        if index < len(positional):
            return positional[index]
        return None  # Would raise IndexError at runtime

    for keyword in keywords:
        if keyword.arg == field.root:
            return keyword.value

    return None  # Would raise KeyError at runtime


def _is_literal(node):
    if _Constant is not None and isinstance(node, _Constant):
        return True

    literal_types = (
        ast.Str, ast.Bytes, ast.Num,
        ast.NameConstant, ast.List, ast.Tuple, ast.Set, ast.Dict,
    )

    return isinstance(node, literal_types)


def _evaluate_target(target, field, capabilities, call_node):
    attribute_steps = [
        step.value for step in field.path if step.kind == STEP_ATTRIBUTE
    ]

    # Plain "{obj}" and index-only fields only stringify or subscript the
    # object, which cannot traverse into restricted attributes.
    if not attribute_steps:
        return None

    # Literals are author-controlled constants, not untrusted objects.
    if _is_literal(target):
        return None

    if isinstance(target, ast.Name):
        object_name = target.id
    else:
        object_name = None

    if object_name is None or object_name not in capabilities:
        return Finding(
            kind=KIND_UNKNOWN_OBJECT,
            lineno=call_node.lineno,
            col_offset=call_node.col_offset,
            field=field.raw,
            object_name=object_name
        )

    permitted_attributes = capabilities[object_name]

    for attribute in attribute_steps:
        if attribute not in permitted_attributes:
            return Finding(
                kind=KIND_UNSAFE_ATTRIBUTE,
                lineno=call_node.lineno,
                col_offset=call_node.col_offset,
                field=field.raw,
                object_name=object_name
            )

    return None


class _ModuleFacts(object):
    """Collects module-level facts used to statically resolve strings.

    Tracks simple assignments and project-internal constant wrapper
    functions (e.g. "def CONST(s): return s") so that format strings
    remain analyzable after passing through them.
    """

    def __init__(self, module_node):
        self.assignments = collections.defaultdict(list)
        self.mutated_names = set()
        self.functions = {}

        for node in ast.walk(module_node):
            if isinstance(node, ast.Assign):
                if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    self.assignments[node.targets[0].id].append(node.value)
            elif isinstance(node, ast.AugAssign):
                if isinstance(node.target, ast.Name):
                    self.mutated_names.add(node.target.id)
            elif _AnnAssign is not None and isinstance(node, _AnnAssign):
                if isinstance(node.target, ast.Name):
                    self.mutated_names.add(node.target.id)
            elif isinstance(node, _function_def_types):
                self.functions[node.name] = node

    def resolve_string(self, node, depth=0):
        """Statically resolve an expression to a string, or return None."""
        if depth > MAX_RESOLUTION_DEPTH:
            return None

        value = _string_constant_value(node)
        if value is not None:
            return value

        if isinstance(node, ast.Name):
            if node.id in self.mutated_names:
                return None
            values = self.assignments.get(node.id)
            if values is None or len(values) != 1:
                return None
            return self.resolve_string(values[0], depth=depth + 1)

        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self.resolve_string(node.left, depth=depth + 1)
            right = self.resolve_string(node.right, depth=depth + 1)
            if left is None or right is None:
                return None
            return left + right

        if isinstance(node, ast.Call):
            return self._resolve_wrapper_call(node, depth)

        return None

    def _resolve_wrapper_call(self, node, depth):
        if not isinstance(node.func, ast.Name):
            return None

        function = self.functions.get(node.func.id)
        if function is None:
            return None

        wrapper = _classify_constant_wrapper(function)
        if wrapper is None:
            return None

        kind, value = wrapper

        if kind == 'constant':
            return value

        # Identity wrapper: resolve the argument bound to the parameter
        parameter_name = value
        argument = _find_argument(node, function, parameter_name)
        if argument is None:
            return None

        return self.resolve_string(argument, depth=depth + 1)


def _string_constant_value(node):
    if _Constant is not None and isinstance(node, _Constant):
        if isinstance(node.value, string_types):
            return node.value
        return None

    if isinstance(node, ast.Str):
        return node.s

    return None


def _classify_constant_wrapper(function):
    """Classify "def WRAP(s): return s" style functions.

    Returns ('identity', parameter_name) for functions returning one of
    their parameters, ('constant', value) for functions returning a
    string constant, or None for anything else.
    """
    body = function.body

    # Allow a leading docstring
    if (body
            and isinstance(body[0], ast.Expr)
            and _string_constant_value(body[0].value) is not None):
        body = body[1:]

    if len(body) != 1 or not isinstance(body[0], ast.Return):
        return None

    return_value = body[0].value
    if return_value is None:
        return None

    constant = _string_constant_value(return_value)
    if constant is not None:
        return ('constant', constant)

    if isinstance(return_value, ast.Name):
        parameter_names = [arg.arg for arg in function.args.args]
        if return_value.id in parameter_names:
            return ('identity', return_value.id)

    return None


def _find_argument(call, function, parameter_name):
    parameter_names = [arg.arg for arg in function.args.args]

    if parameter_name in parameter_names:
        position = parameter_names.index(parameter_name)
        if position < len(call.args):
            return call.args[position]

    for keyword in call.keywords:
        if keyword.arg == parameter_name:
            return keyword.value

    return None
