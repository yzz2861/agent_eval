#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast

from ... import tree


CLASSIFIED_TERMS = (
    'classified',
    'confidential',
    'private',
    'restricted',
    'secret',
    'sensitive',
)

PUBLIC_TERMS = (
    'public',
    'redacted',
    'sanitized',
)

DEBUG_EXPORT_TERMS = (
    'debug',
)

EXPORT_TERMS = (
    'dump',
    'emit',
    'export',
    'log',
    'output',
    'sink',
    'trace',
    'write',
)

PUBLIC_ONLY_KWARGS = (
    'only_public',
    'public_fields_only',
    'public_only',
)

CLASSIFICATION_KWARGS = (
    'classification',
    'classification_level',
    'secrecy',
    'sensitivity',
)

PUBLIC_CLASSIFICATIONS = (
    'none',
    'open',
    'public',
    'unclassified',
)

EMPTY_ORIGINS = frozenset()
AST_CONSTANT = getattr(ast, 'Constant', None)
AST_NAME_CONSTANT = getattr(ast, 'NameConstant', None)
AST_INDEX = getattr(ast, 'Index', None)


def _tokens(name):
    normalized = []
    for character in name:
        if character.isupper():
            normalized.append('_')
            normalized.append(character.lower())
        else:
            normalized.append(character)

    return tuple(
        token
        for token in ''.join(normalized).replace('.', '_').split('_')
        if token
    )


def _contains_term(name, terms):
    lower_name = name.lower()
    tokens = _tokens(name)

    return any(
        term in lower_name or term in tokens
        for term in terms
    )


def _literal_classification(node):
    if isinstance(node, ast.Str):
        return node.s.lower()

    if (
            AST_CONSTANT is not None
            and isinstance(node, AST_CONSTANT)
            and isinstance(node.value, str)):
        return node.value.lower()

    return None


def _literal_is_public(node):
    classification = _literal_classification(node)

    if classification is not None:
        return classification in PUBLIC_CLASSIFICATIONS

    if (
            AST_NAME_CONSTANT is not None
            and isinstance(node, AST_NAME_CONSTANT)):
        return node.value is None

    if AST_CONSTANT is not None and isinstance(node, AST_CONSTANT):
        return node.value is None

    return False


def _annotation_name(annotation):
    if annotation is None:
        return ''

    return tree.module_path_str(annotation)


def _public_path(name):
    return _contains_term(name, PUBLIC_TERMS)


def _expression_label(node):
    if isinstance(node, (ast.Name, ast.Attribute)):
        return tree.module_path_str(node)
    elif isinstance(node, ast.Call):
        return _expression_label(node.func)
    elif isinstance(node, ast.Subscript):
        return _expression_label(node.value)

    return ''


def _classified_name(name):
    return _contains_term(name, CLASSIFIED_TERMS)


def _debug_export_name(name):
    return (
        _contains_term(name, DEBUG_EXPORT_TERMS)
        and _contains_term(name, EXPORT_TERMS)
    )


def _public_only_call(node):
    for keyword in node.keywords:
        if keyword.arg in PUBLIC_ONLY_KWARGS:
            if not _literal_is_public(keyword.value):
                return True

    return False


def _debug_export_call(node, callee_name):
    return _debug_export_name(callee_name) or _public_only_call(node)


def _classified_call(node, callee_name):
    if _classified_name(callee_name):
        return True

    for keyword in node.keywords:
        if (
                keyword.arg in CLASSIFICATION_KWARGS
                and not _literal_is_public(keyword.value)):
            return True

    return False


class Origin(object):
    __slots__ = ('kind', 'label', 'lineno', 'col_offset')

    def __init__(self, kind, label, lineno, col_offset):
        self.kind = kind
        self.label = label
        self.lineno = lineno
        self.col_offset = col_offset

    def __eq__(self, other):
        return (
            isinstance(other, Origin)
            and self._key() == other._key()
        )

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(self._key())

    def _key(self):
        return (self.kind, self.label, self.lineno, self.col_offset)

    def sort_key(self):
        return (self.lineno, self.col_offset, self.kind, self.label)

    def path_sort_key(self):
        source_priority = 0 if self.kind == 'source' else 1
        return (
            source_priority,
            self.lineno,
            self.col_offset,
            self.kind,
            self.label,
        )

    def describe(self):
        location = '{}:{}'.format(self.lineno, self.col_offset)

        if self.kind == 'source':
            return 'classified source "{}" at {}'.format(self.label, location)
        elif self.kind == 'yield':
            return 'yield at {}'.format(location)
        elif self.kind == 'delegated yield':
            return 'yield from "{}" at {}'.format(self.label, location)
        elif self.kind == 'return':
            return 'return at {}'.format(location)
        elif self.kind == 'send':
            return 'send at {}'.format(location)
        elif self.kind == 'uncertain call':
            return 'uncertain call "{}" at {}'.format(self.label, location)
        else:
            return '{} "{}" at {}'.format(self.kind, self.label, location)


def _origins(*items):
    return frozenset(item for item in items if item is not None)


def _origin_set(value):
    if value is None:
        return EMPTY_ORIGINS

    if isinstance(value, Origin):
        return frozenset((value,))

    return frozenset(value)


class FlowValue(object):
    __slots__ = ('direct', 'iterated', 'returned')

    def __init__(
            self,
            direct=EMPTY_ORIGINS,
            iterated=EMPTY_ORIGINS,
            returned=EMPTY_ORIGINS):
        self.direct = _origin_set(direct)
        self.iterated = _origin_set(iterated)
        self.returned = _origin_set(returned)

    def __eq__(self, other):
        return (
            isinstance(other, FlowValue)
            and self._key() == other._key()
        )

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(self._key())

    def _key(self):
        return (
            tuple(sorted(self.direct, key=lambda origin: origin.sort_key())),
            tuple(sorted(self.iterated, key=lambda origin: origin.sort_key())),
            tuple(sorted(self.returned, key=lambda origin: origin.sort_key())),
        )

    def exposed(self):
        return frozenset(
            origin
            for origin in self.direct.union(self.iterated)
            if origin.kind != 'send'
        )

    def iteration_value(self):
        if self.iterated:
            return FlowValue(direct=self.iterated)

        return FlowValue(direct=self.direct)

    def substitute_send(self, sent_value, send_origin):
        if not self._contains_send():
            return self

        sent_origins = sent_value.direct.union(sent_value.iterated)

        def substitute(origins):
            substituted = set()
            for origin in origins:
                if origin.kind == 'send':
                    substituted.update(sent_origins)
                    substituted.add(send_origin)
                else:
                    substituted.add(origin)
            return substituted

        return FlowValue(
            direct=substitute(self.direct),
            iterated=substitute(self.iterated),
            returned=substitute(self.returned),
        )

    def _contains_send(self):
        return any(
            origin.kind == 'send'
            for origin in self.direct.union(self.iterated).union(self.returned)
        )


EMPTY_VALUE = FlowValue()


def merge_values(values):
    direct = set()
    iterated = set()
    returned = set()

    for value in values:
        direct.update(value.direct)
        iterated.update(value.iterated)
        returned.update(value.returned)

    return FlowValue(
        direct=direct,
        iterated=iterated,
        returned=returned,
    )


def merge_states(states):
    names = set()
    for state in states:
        names.update(state)

    return {
        name: merge_values(
            state.get(name, EMPTY_VALUE)
            for state in states
        )
        for name in names
    }


def _tag_origins(origins, kind, label, node):
    if not origins:
        return EMPTY_ORIGINS

    return frozenset(origins).union((
        Origin(kind, label, node.lineno, node.col_offset),
    ))


class FunctionSummary(object):
    __slots__ = ('yielded', 'returned', 'is_generator')

    def __init__(
            self,
            yielded=EMPTY_ORIGINS,
            returned=EMPTY_ORIGINS,
            is_generator=False):
        self.yielded = _origin_set(yielded)
        self.returned = _origin_set(returned)
        self.is_generator = is_generator

    def key(self):
        return (
            tuple(sorted(self.yielded, key=lambda origin: origin.sort_key())),
            tuple(sorted(self.returned, key=lambda origin: origin.sort_key())),
            self.is_generator,
        )


class Violation(object):
    __slots__ = ('node', 'sink', 'origins')

    def __init__(self, node, sink, origins):
        self.node = node
        self.sink = sink
        self.origins = frozenset(
            origin
            for origin in origins
            if origin.kind != 'send'
        )

    def key(self):
        return (
            self.node.lineno,
            self.node.col_offset,
            self.sink,
            tuple(
                origin.sort_key()
                for origin in sorted(
                    self.origins,
                    key=lambda origin: origin.sort_key(),
                )
            ),
        )


def _function_nodes(module):
    functions = []

    def collect(body, prefix):
        for node in body:
            if isinstance(node, (ast.FunctionDef, getattr(ast, 'AsyncFunctionDef', ast.FunctionDef))):
                name = node.name
                qualified_name = '{}{}'.format(prefix, name)
                functions.append((qualified_name, node))
                collect(node.body, '{}.'.format(qualified_name))
            elif isinstance(node, ast.ClassDef):
                collect(
                    node.body,
                    '{}{}.'.format(prefix, node.name),
                )

    collect(module.body, '')

    return functions


def _function_is_generator(node):
    scopes = (ast.FunctionDef, ast.ClassDef)
    async_function = getattr(ast, 'AsyncFunctionDef', None)
    if async_function is not None:
        scopes += (async_function,)

    yield_nodes = (ast.Yield, getattr(ast, 'YieldFrom', ast.Yield))
    found = []

    def walk(inner_node):
        for child in ast.iter_child_nodes(inner_node):
            if child is not node and isinstance(child, scopes):
                continue
            if isinstance(child, yield_nodes):
                found.append(child)
            walk(child)

    walk(node)

    return bool(found)


class Analyzer(object):
    def __init__(self, module, filename=None):
        self.module = module
        self.filename = filename
        self.functions = {}
        self.function_nodes = []
        self.globals = {}
        self.violations = []
        self._violation_keys = set()
        self._cache = {}

        for qualified_name, node in _function_nodes(module):
            self.function_nodes.append(node)
            self._index_function(qualified_name, node)

    def _index_function(self, qualified_name, node):
        for name in set((qualified_name, node.name)):
            self.functions.setdefault(name, []).append(node)

    def resolve_function(self, callee_name):
        parts = callee_name.split('.')

        if parts and parts[0] in ('self', 'cls'):
            callee_name = parts[-1]

        candidates = self.functions.get(callee_name, [])
        if len(candidates) == 1:
            return candidates[0]

        return None

    def run(self):
        module_runner = FunctionAnalysis(
            analyzer=self,
            function=None,
            arguments={},
            stack=(),
            initial_state={},
        )
        self.globals = module_runner.run_body(self.module.body)

        for function in self.function_nodes:
            self.analyze(function)

        return self.violations

    def analyze(self, function, arguments=None, stack=()):
        arguments = arguments or {}
        if function in stack:
            return FunctionSummary(is_generator=_function_is_generator(function))

        cache_key = (
            id(function),
            tuple(
                sorted(
                    (name, value._key())
                    for name, value in arguments.items()
                )
            ),
        )
        if cache_key in self._cache:
            return self._cache[cache_key]

        runner = FunctionAnalysis(
            analyzer=self,
            function=function,
            arguments=arguments,
            stack=stack + (function,),
            initial_state={},
        )
        summary = runner.run()
        self._cache[cache_key] = summary

        return summary

    def add_violation(self, node, sink, origins):
        violation = Violation(node, sink, origins)
        if not violation.origins or violation.key() in self._violation_keys:
            return

        self._violation_keys.add(violation.key())
        self.violations.append(violation)


class FunctionAnalysis(object):
    def __init__(self, analyzer, function, arguments, stack, initial_state):
        self.analyzer = analyzer
        self.function = function
        self.arguments = arguments
        self.stack = stack
        self.state = dict(initial_state)
        self.yielded = set()
        self.returned = set()
        self.is_generator = (
            _function_is_generator(function)
            if function is not None
            else False
        )

    def run(self):
        if self.function is None:
            self.state = self.run_body(self.analyzer.module.body)
        else:
            self.state = self._parameter_state()
            self.state = self.run_body(self.function.body)

        return FunctionSummary(
            yielded=self.yielded,
            returned=self.returned,
            is_generator=self.is_generator,
        )

    def _parameter_state(self):
        state = {}
        function_arguments = list(getattr(self.function.args, 'posonlyargs', ()))
        function_arguments.extend(self.function.args.args)
        function_arguments.extend(self.function.args.kwonlyargs)

        for argument in function_arguments:
            if argument.arg in self.arguments:
                state[argument.arg] = self.arguments[argument.arg]
                continue

            annotation = _annotation_name(argument.annotation)
            if _classified_name(argument.arg) or _classified_name(annotation):
                state[argument.arg] = FlowValue(
                    direct=Origin(
                        'source',
                        argument.arg,
                        getattr(argument, 'lineno', self.function.lineno),
                        getattr(argument, 'col_offset', self.function.col_offset),
                    ),
                )

        return state

    def run_body(self, body):
        state = dict(self.state)
        for statement in body:
            state = self.run_statement(statement, state)
        self.state = state

        return state

    def run_statement(self, node, state):
        if isinstance(node, ast.Assign):
            value = self.eval(node.value, state)
            for target in node.targets:
                self.assign(target, value, state)
        elif isinstance(node, ast.AnnAssign):
            if node.value is not None:
                value = self.eval(node.value, state)
                self.assign(node.target, value, state)
        elif isinstance(node, ast.AugAssign):
            value = self.eval(node.value, state)
            previous = self.eval(node.target, state)
            self.assign(node.target, merge_values((previous, value)), state)
        elif isinstance(node, ast.Expr):
            self.eval(node.value, state)
        elif isinstance(node, ast.Return):
            value = self.eval(node.value, state) if node.value is not None else EMPTY_VALUE
            self.returned.update(
                _tag_origins(value.direct, 'return', '', node)
            )
        elif isinstance(node, ast.If):
            self.eval(node.test, state)
            left = self._run_block_in_state(node.body, dict(state))
            right = self._run_block_in_state(node.orelse, dict(state))
            state = merge_states((left, right))
        elif isinstance(node, ast.For):
            iterable = self.eval(node.iter, state)
            loop_state = dict(state)
            self.assign(node.target, iterable.iteration_value(), loop_state)
            loop_state = self._run_block_in_state(node.body, loop_state)
            loop_state = self._run_block_in_state(node.body, loop_state)
            state = merge_states((state, loop_state))
        elif isinstance(node, ast.While):
            self.eval(node.test, state)
            loop_state = self._run_block_in_state(node.body, dict(state))
            loop_state = self._run_block_in_state(node.body, loop_state)
            state = merge_states((state, loop_state))
        elif isinstance(node, ast.With):
            with_state = dict(state)
            for item in node.items:
                self.eval(item.context_expr, with_state)
                if item.optional_vars is not None:
                    self.assign(
                        item.optional_vars,
                        EMPTY_VALUE,
                        with_state,
                    )
            state = self._run_block_in_state(node.body, with_state)
        elif isinstance(node, ast.Try):
            body_state = self._run_block_in_state(node.body, dict(state))
            handler_states = [body_state]
            for handler in node.handlers:
                handler_state = self._run_block_in_state(
                    handler.body,
                    merge_states((state, body_state)),
                )
                handler_states.append(handler_state)
            merged = merge_states(handler_states)
            if node.finalbody:
                merged = self._run_block_in_state(node.finalbody, merged)
            state = merged
        elif isinstance(node, ast.Assert):
            self.eval(node.test, state)
            if node.msg is not None:
                self.eval(node.msg, state)
        elif isinstance(node, ast.Raise):
            if node.exc is not None:
                self.eval(node.exc, state)
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    state.pop(target.id, None)
        elif isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            return state
        elif isinstance(node, getattr(ast, 'AsyncFunctionDef', ast.FunctionDef)):
            return state
        elif isinstance(node, getattr(ast, 'AsyncFor', ast.For)):
            iterable = self.eval(node.iter, state)
            loop_state = dict(state)
            self.assign(node.target, iterable.iteration_value(), loop_state)
            state = merge_states((
                state,
                self._run_block_in_state(node.body, loop_state),
            ))
        elif isinstance(node, getattr(ast, 'AsyncWith', ast.With)):
            with_state = dict(state)
            for item in node.items:
                self.eval(item.context_expr, with_state)
                if item.optional_vars is not None:
                    self.assign(item.optional_vars, EMPTY_VALUE, with_state)
            state = self._run_block_in_state(node.body, with_state)

        return state

    def _run_block_in_state(self, body, state):
        previous_state = self.state
        self.state = state
        result = self.run_body(body)
        self.state = previous_state

        return result

    def assign(self, target, value, state):
        if isinstance(target, ast.Name):
            state[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            item_value = value.iteration_value()
            for element in target.elts:
                self.assign(element, item_value, state)
        elif isinstance(target, ast.Starred):
            self.assign(target.value, value.iteration_value(), state)
        elif isinstance(target, ast.Attribute):
            self.eval(target.value, state)
        elif isinstance(target, ast.Subscript):
            self.eval(target.value, state)
            self.eval(target.slice, state)

    def eval(self, node, state):
        if node is None:
            return EMPTY_VALUE

        if isinstance(node, ast.Name):
            if node.id in state:
                return state[node.id]
            if node.id in self.analyzer.globals:
                return self.analyzer.globals[node.id]
            if _classified_name(node.id):
                return FlowValue(
                    direct=Origin(
                        'source',
                        node.id,
                        node.lineno,
                        node.col_offset,
                    ),
                )
            return EMPTY_VALUE
        elif isinstance(node, ast.Attribute):
            name = tree.module_path_str(node)
            if _public_path(name):
                return EMPTY_VALUE

            value = self.eval(node.value, state)
            origins = value.direct.union(value.iterated)
            if _classified_name(node.attr):
                origins = origins.union((
                    Origin(
                        'source',
                        name,
                        node.lineno,
                        node.col_offset,
                    ),
                ))

            return FlowValue(direct=origins)
        elif isinstance(node, ast.Call):
            return self.eval_call(node, state)
        elif isinstance(node, ast.Yield):
            value = self.eval(node.value, state) if node.value is not None else EMPTY_VALUE
            self.yielded.update(
                _tag_origins(
                    value.direct.union(value.iterated),
                    'yield',
                    '',
                    node,
                )
            )

            return FlowValue(
                direct=Origin(
                    'send',
                    '',
                    node.lineno,
                    node.col_offset,
                ),
            )
        elif isinstance(node, getattr(ast, 'YieldFrom', ast.Yield)):
            value = self.eval(node.value, state)
            delegated = value.iterated or value.direct
            label = _expression_label(node.value)
            self.yielded.update(
                _tag_origins(
                    delegated,
                    'delegated yield',
                    label,
                    node,
                )
            )

            return FlowValue(direct=value.returned)
        elif isinstance(node, ast.Tuple):
            return merge_values(self.eval(element, state) for element in node.elts)
        elif isinstance(node, ast.List):
            value = merge_values(self.eval(element, state) for element in node.elts)
            return FlowValue(
                direct=value.direct,
                iterated=value.direct,
            )
        elif isinstance(node, ast.Set):
            value = merge_values(self.eval(element, state) for element in node.elts)
            return FlowValue(
                direct=value.direct,
                iterated=value.direct,
            )
        elif isinstance(node, ast.Dict):
            values = []
            for key, value in zip(node.keys, node.values):
                if key is not None:
                    values.append(self.eval(key, state))
                values.append(self.eval(value, state))
            merged = merge_values(values)
            return FlowValue(
                direct=merged.direct,
                iterated=merged.direct,
            )
        elif isinstance(node, ast.BinOp):
            return merge_values((
                self.eval(node.left, state),
                self.eval(node.right, state),
            ))
        elif isinstance(node, ast.BoolOp):
            return merge_values(self.eval(value, state) for value in node.values)
        elif isinstance(node, ast.UnaryOp):
            return self.eval(node.operand, state)
        elif isinstance(node, ast.Compare):
            values = [self.eval(node.left, state)]
            values.extend(self.eval(comparator, state) for comparator in node.comparators)
            return merge_values(values)
        elif isinstance(node, ast.IfExp):
            self.eval(node.test, state)
            return merge_values((
                self.eval(node.body, state),
                self.eval(node.orelse, state),
            ))
        elif isinstance(node, ast.Subscript):
            name = tree.module_path_str(node.value)
            if self._public_subscript(node, name):
                return EMPTY_VALUE

            value = self.eval(node.value, state)
            return FlowValue(direct=value.direct.union(value.iterated))
        elif isinstance(node, ast.Starred):
            return self.eval(node.value, state)
        elif isinstance(node, ast.Await):
            return self.eval(node.value, state)
        elif isinstance(node, ast.Lambda):
            return EMPTY_VALUE
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            comprehension_state = self._comprehension_state(node, state)
            value = self.eval(node.elt, comprehension_state)
            return FlowValue(
                direct=value.direct,
                iterated=value.direct,
            )
        elif isinstance(node, ast.DictComp):
            comprehension_state = self._comprehension_state(node, state)
            value = merge_values((
                self.eval(node.key, comprehension_state),
                self.eval(node.value, comprehension_state),
            ))
            return FlowValue(
                direct=value.direct,
                iterated=value.direct,
            )
        elif isinstance(node, ast.JoinedStr):
            return merge_values(
                self.eval(value, state)
                for value in node.values
            )
        elif isinstance(node, ast.FormattedValue):
            return self.eval(node.value, state)

        return EMPTY_VALUE

    def _comprehension_state(self, node, state):
        comprehension_state = dict(state)
        for generator in node.generators:
            iterable = self.eval(generator.iter, comprehension_state)
            self.assign(
                generator.target,
                iterable.iteration_value(),
                comprehension_state,
            )
            for condition in generator.ifs:
                self.eval(condition, comprehension_state)

        return comprehension_state

    def _public_subscript(self, node, name):
        if _public_path(name):
            return True

        key = node.slice
        if AST_INDEX is not None and isinstance(key, AST_INDEX):
            key = key.value

        classification = _literal_classification(key)

        return (
            classification is not None
            and _public_path(classification)
        )

    def eval_call(self, node, state):
        callee = tree.module_path_str(node.func)

        if _debug_export_call(node, callee):
            values = [
                self.eval(argument, state)
                for argument in node.args
            ]
            values.extend(
                self.eval(keyword.value, state)
                for keyword in node.keywords
            )
            origins = set()
            for value in values:
                origins.update(value.exposed())
            self.analyzer.add_violation(node, callee, origins)

            return EMPTY_VALUE

        if _public_path(callee):
            for argument in node.args:
                self.eval(argument, state)
            for keyword in node.keywords:
                self.eval(keyword.value, state)
            return EMPTY_VALUE

        if isinstance(node.func, ast.Attribute):
            method_name = node.func.attr
            if method_name == 'send':
                receiver = self.eval(node.func.value, state)
                sent_value = (
                    self.eval(node.args[0], state)
                    if node.args
                    else EMPTY_VALUE
                )
                send_origin = Origin(
                    'send',
                    callee,
                    node.lineno,
                    node.col_offset,
                )
                sent = receiver.substitute_send(sent_value, send_origin)

                return FlowValue(
                    direct=sent.iterated,
                    iterated=sent.iterated,
                    returned=sent.returned,
                )
            elif method_name in ('close', 'throw'):
                self.eval(node.func.value, state)
                for argument in node.args:
                    self.eval(argument, state)
                return EMPTY_VALUE

        function = self.analyzer.resolve_function(callee)
        if function is not None:
            arguments = {}
            function_arguments = list(getattr(function.args, 'posonlyargs', ()))
            function_arguments.extend(function.args.args)
            for function_argument, value in zip(function_arguments, node.args):
                arguments[function_argument.arg] = self.eval(value, state)
            for keyword in node.keywords:
                arguments[keyword.arg] = self.eval(keyword.value, state)

            summary = self.analyzer.analyze(function, arguments, self.stack)
            if summary.is_generator:
                return FlowValue(
                    iterated=summary.yielded,
                    returned=summary.returned,
                )
            else:
                return FlowValue(direct=summary.returned)

        builtin = self._eval_builtin(node, callee, state)
        if builtin is not None:
            return builtin

        if _classified_call(node, callee):
            return FlowValue(
                direct=Origin(
                    'source',
                    callee,
                    node.lineno,
                    node.col_offset,
                ),
            )

        values = [
            self.eval(argument, state)
            for argument in node.args
        ]
        values.extend(
            self.eval(keyword.value, state)
            for keyword in node.keywords
        )
        exposed = set()
        for value in values:
            exposed.update(value.exposed())

        if exposed:
            origin = Origin(
                'uncertain call',
                callee or '<dynamic>',
                node.lineno,
                node.col_offset,
            )
            return FlowValue(
                direct=exposed.union((origin,)),
                iterated=exposed.union((origin,)),
            )

        return EMPTY_VALUE

    def _eval_builtin(self, node, callee, state):
        if callee in ('iter', 'list', 'set', 'tuple', 'frozenset'):
            if not node.args:
                return EMPTY_VALUE
            value = self.eval(node.args[0], state)
            return FlowValue(
                direct=value.iterated or value.direct,
                iterated=value.iterated or value.direct,
            )
        elif callee == 'next':
            if not node.args:
                return EMPTY_VALUE
            value = self.eval(node.args[0], state)
            return FlowValue(direct=value.iterated or value.direct)
        elif callee in ('enumerate', 'filter', 'map', 'reversed', 'zip'):
            value = merge_values(
                self.eval(argument, state)
                for argument in node.args
            )
            direct = value.iterated or value.direct
            return FlowValue(direct=direct, iterated=direct)

        return None
