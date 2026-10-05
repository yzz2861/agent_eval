from __future__ import annotations

import ast
import io
import tokenize
from tokenize import NL, OP, STRING, generate_tokens

from babel.util import parse_encoding, parse_future_flags


class _ModuleBinding:
    __slots__ = ('parts',)

    def __init__(self, parts: tuple[str, ...]):
        self.parts = parts


class _ImportedFunctionBinding:
    __slots__ = ('module', 'name', 'level')

    def __init__(self, module: tuple[str, ...], name: str, level: int = 0):
        self.module = module
        self.name = name
        self.level = level


_UNKNOWN = object()
FSTRING_START = getattr(tokenize, 'FSTRING_START', None)
FSTRING_MIDDLE = getattr(tokenize, 'FSTRING_MIDDLE', None)
FSTRING_END = getattr(tokenize, 'FSTRING_END', None)


def extract_python_scope_aware(fileobj, keywords, comment_tags, options):
    encoding = parse_encoding(fileobj) or options.get('encoding', 'UTF-8')
    future_flags = parse_future_flags(fileobj, encoding)
    source = fileobj.read().decode(encoding)
    if source.startswith('\ufeff'):
        source = source[1:]
    yield from _ScopeExtractor(
        source, set(keywords), comment_tags, encoding, future_flags,
    ).extract()


class _ScopeExtractor:
    def __init__(self, source, keywords, comment_tags, encoding, future_flags):
        self.source = source
        self.lines = source.splitlines()
        self.keywords = set(keywords)
        self.comment_tags = tuple(comment_tags)
        self.encoding = encoding
        self.future_flags = future_flags
        self.tree = ast.parse(source)
        self.tokens = list(generate_tokens(io.StringIO(source).readline))
        self.token_positions = {token.start: i for i, token in enumerate(self.tokens)}
        self.frames = []
        self.depth = 0
        self.tainted_attrs = set()
        self.tainted_names = set()
        self.analysis_only = True
        self.recognized_ids = set()
        for _ in self.visit(self.tree):
            pass
        self.analysis_only = False
        self._reset()
        self.openings = self._map_openings()
        self.opening_by_token = {index: call_id for call_id, index in self.openings.items()}

    def _reset(self):
        self.frames = []
        self.depth = 0
        self.tainted_attrs.clear()
        self.tainted_names.clear()

    def extract(self):
        return list(self.visit(self.tree))

    def visit(self, node):
        method = getattr(self, 'visit_' + type(node).__name__, self.generic_visit)
        result = method(node)
        if result is not None:
            yield from result

    def generic_visit(self, node):
        for child in ast.iter_child_nodes(node):
            yield from self.visit(child)

    @property
    def frame(self):
        return self.frames[-1]

    def _map_openings(self):
        result = {}
        for call in ast.walk(self.tree):
            if not isinstance(call, ast.Call) or id(call) not in self.recognized_ids:
                continue
            index = self.token_positions.get((call.func.end_lineno, call.func.end_col_offset))
            if index is None:
                continue
            for token_index in range(index, len(self.tokens)):
                token = self.tokens[token_index]
                if token.type == OP and token.string == '(':
                    result[id(call)] = token_index
                    break
        return result

    def visit_Module(self, node):
        self.frames.append(self._frame('module'))
        try:
            for statement in node.body:
                yield from self.visit(statement)
        finally:
            self.frames.pop()

    def visit_FunctionDef(self, node):
        yield from self._visit_function(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def _visit_function(self, node):
        for decorator in node.decorator_list:
            yield from self.visit(decorator)
        yield from self.visit(node.args)
        if node.returns is not None:
            yield from self.visit(node.returns)
        self._enter_function(node)
        try:
            for statement in node.body:
                yield from self.visit(statement)
        finally:
            parent = self.frames[-2]
            for name in self.frames[-1]['globals']:
                if self._assigns_name(node, name):
                    self.tainted_names.add(name)
            self.frames.pop()
        if node.name not in parent.get('globals', ()):
            self._assign(node.name, _UNKNOWN)

    def visit_Lambda(self, node):
        yield from self.visit(node.args)
        self._enter_function(node)
        try:
            yield from self.visit(node.body)
        finally:
            self.frames.pop()

    def visit_arguments(self, node):
        for default in node.defaults + node.kw_defaults:
            if default is not None:
                yield from self.visit(default)
        for arg in node.posonlyargs + node.args + node.kwonlyargs:
            if arg.annotation is not None:
                yield from self.visit(arg.annotation)
        for arg in (node.vararg, node.kwarg):
            if arg is not None and arg.annotation is not None:
                yield from self.visit(arg.annotation)

    def visit_arg(self, node):
        if node.annotation is not None:
            yield from self.visit(node.annotation)

    def visit_ClassDef(self, node):
        for decorator in node.decorator_list:
            yield from self.visit(decorator)
        for base in node.bases:
            yield from self.visit(base)
        for keyword in node.keywords:
            yield from self.visit(keyword)
        self.frames.append(self._frame('class'))
        try:
            for statement in node.body:
                yield from self.visit(statement)
        finally:
            self.frames.pop()
        self._assign(node.name, _UNKNOWN)

    def visit_ListComp(self, node):
        yield from self._visit_comprehension(node, node.elt)

    visit_SetComp = visit_GeneratorExp = visit_ListComp

    def visit_DictComp(self, node):
        yield from self.visit(node.generators[0].iter)
        self._push_comprehension(node)
        try:
            for generator in node.generators[1:]:
                yield from self.visit(generator.iter)
                for test in generator.ifs:
                    yield from self.visit(test)
            for generator in node.generators[:1]:
                for test in generator.ifs:
                    yield from self.visit(test)
            yield from self.visit(node.key)
            yield from self.visit(node.value)
        finally:
            self.frames.pop()

    def _visit_comprehension(self, node, element):
        yield from self.visit(node.generators[0].iter)
        self._push_comprehension(node)
        try:
            for generator in node.generators[1:]:
                yield from self.visit(generator.iter)
                for test in generator.ifs:
                    yield from self.visit(test)
            for test in node.generators[0].ifs:
                yield from self.visit(test)
            yield from self.visit(element)
        finally:
            self.frames.pop()

    def _frame(self, kind):
        return {'kind': kind, 'bindings': {}, 'locals': set(),
                'globals': set(), 'nonlocals': set(), 'nonlocal_assignments': set()}

    def _push_comprehension(self, node):
        names = self._comprehension_names(node)
        self.frames.append({'kind': 'function', 'bindings': dict.fromkeys(names, _UNKNOWN),
                            'locals': names, 'globals': set(), 'nonlocals': set(),
                            'nonlocal_assignments': set()})

    def _enter_function(self, node):
        locals_, globals_, nonlocals_ = self._function_names(node)
        self.frames.append({'kind': 'function', 'bindings': dict.fromkeys(locals_, _UNKNOWN),
                            'locals': locals_, 'globals': globals_, 'nonlocals': nonlocals_,
                            'nonlocal_assignments': set()})

    def _function_names(self, node):
        names = self._argument_names(node.args)
        globals_ = set()
        nonlocals_ = set()
        body = [node.body] if isinstance(node, ast.Lambda) else node.body

        class Visitor(ast.NodeVisitor):
            def visit_FunctionDef(self, child):
                names.add(child.name)

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_ClassDef(self, child):
                names.add(child.name)

            def visit_Lambda(self, child):
                return

            def visit_ListComp(self, child):
                return

            visit_SetComp = visit_DictComp = visit_GeneratorExp = visit_ListComp

            def visit_Import(self, child):
                names.update(_import_names(child))

            def visit_ImportFrom(self, child):
                names.update(_import_names(child))

            def visit_Name(self, child):
                if isinstance(child.ctx, ast.Store) and child.id not in globals_:
                    names.add(child.id)

            def visit_ExceptHandler(self, child):
                if child.name:
                    names.add(child.name)
                self.generic_visit(child)

            def visit_Global(self, child):
                globals_.update(child.names)
                names.difference_update(child.names)

            def visit_Nonlocal(self, child):
                nonlocals_.update(child.names)

        visitor = Visitor()
        for statement in body:
            visitor.visit(statement)
        names.difference_update(globals_)
        names.difference_update(nonlocals_)
        return names, globals_, nonlocals_

    @staticmethod
    def _argument_names(arguments):
        names = {arg.arg for arg in arguments.posonlyargs + arguments.args + arguments.kwonlyargs}
        if arguments.vararg is not None:
            names.add(arguments.vararg.arg)
        if arguments.kwarg is not None:
            names.add(arguments.kwarg.arg)
        return names

    @staticmethod
    def _comprehension_names(node):
        return {
            child.id
            for generator in node.generators
            for child in ast.walk(generator.target)
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)
        }

    @staticmethod
    def _assigns_name(root, name):
        for node in ast.walk(root):
            if isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, ast.Store):
                return True
        return False

    def resolve(self, name):
        frame = self.frame
        if name in self.tainted_names:
            return _UNKNOWN
        if name in frame['globals']:
            return self.frames[0]['bindings'].get(name, _UNKNOWN)
        if name in frame['nonlocals']:
            if name in frame['nonlocal_assignments']:
                return _UNKNOWN
            for candidate in reversed(self.frames[:-1]):
                if candidate['kind'] == 'function' and name in candidate['locals']:
                    return candidate['bindings'].get(name, _UNKNOWN)
            return _UNKNOWN
        if frame['kind'] == 'function' and name in frame['locals']:
            return frame['bindings'].get(name, _UNKNOWN)
        for candidate in reversed(self.frames):
            if candidate['kind'] == 'class' and candidate is not frame:
                continue
            if name in candidate['bindings']:
                return candidate['bindings'][name]
        return _UNKNOWN

    def assign(self, name, binding):
        frame = self.frame
        if name in frame['globals']:
            self.frames[0]['bindings'][name] = binding
            return
        if name in frame['nonlocals']:
            frame['nonlocal_assignments'].add(name)
            return
        frame['bindings'][name] = binding

    def _assign(self, name, binding):
        self.assign(name, binding)

    def visit_Import(self, node):
        for alias in node.names:
            name = alias.asname or alias.name.split('.')[0]
            self.assign(name, _ModuleBinding(tuple(alias.name.split('.'))))

    def visit_ImportFrom(self, node):
        module = tuple(node.module.split('.')) if node.module else ()
        for alias in node.names:
            if alias.name == '*':
                continue
            name = alias.asname or alias.name
            self.assign(name, _ImportedFunctionBinding(module, alias.name, node.level))

    def visit_Global(self, node):
        return

    def visit_Nonlocal(self, node):
        return

    def visit_Assign(self, node):
        binding = self._binding(node.value)
        yield from self.visit(node.value)
        for target in node.targets:
            self._assign_target(target, binding)

    def visit_AnnAssign(self, node):
        yield from self.visit(node.annotation)
        if node.value is not None:
            binding = self._binding(node.value)
            yield from self.visit(node.value)
            self._assign_target(node.target, binding)

    def visit_AugAssign(self, node):
        yield from self.generic_visit(node)
        if isinstance(node.target, ast.Name):
            self.assign(node.target.id, _UNKNOWN)

    def visit_For(self, node):
        yield from self.visit(node.iter)
        for name in self._store_names(node.target):
            self.assign(name, _UNKNOWN)
        for child in node.body + node.orelse:
            yield from self.visit(child)

    visit_AsyncFor = visit_For

    def visit_With(self, node):
        for item in node.items:
            yield from self.visit(item.context_expr)
            if item.optional_vars is not None:
                for name in self._store_names(item.optional_vars):
                    self.assign(name, _UNKNOWN)
        for statement in node.body:
            yield from self.visit(statement)

    visit_AsyncWith = visit_With

    def visit_ExceptHandler(self, node):
        if node.type is not None:
            yield from self.visit(node.type)
        if node.name:
            self.assign(node.name, _UNKNOWN)
        for statement in node.body:
            yield from self.visit(statement)

    def visit_Delete(self, node):
        yield from self.generic_visit(node)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.assign(target.id, _UNKNOWN)

    def visit_NamedExpr(self, node):
        binding = self._binding(node.value)
        yield from self.visit(node.value)
        self.assign(node.target.id, binding)

    def _assign_target(self, target, binding):
        if isinstance(target, ast.Name):
            self.assign(target.id, binding)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for index, element in enumerate(target.elts):
                if isinstance(element, ast.Starred):
                    self._assign_target(element.value, _UNKNOWN)
                elif isinstance(element, ast.Name):
                    element_binding = (
                        binding[index]
                        if isinstance(binding, tuple) and index < len(binding)
                        else _UNKNOWN
                    )
                    self.assign(element.id, element_binding)
                else:
                    self._assign_target(element, _UNKNOWN)
        elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
            root = self.resolve(target.value.id)
            if isinstance(root, _ModuleBinding):
                self.tainted_attrs.add(root.parts + (target.attr,))

    @staticmethod
    def _store_names(target):
        return [
            node.id for node in ast.walk(target)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
        ]

    def _binding(self, node):
        if isinstance(node, ast.Name):
            return self.resolve(node.id)
        if isinstance(node, (ast.Tuple, ast.List)) and node.elts:
            return tuple(self._binding(element) for element in node.elts)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            root = self.resolve(node.value.id)
            if (
                isinstance(root, _ModuleBinding)
                and root.parts == ('gettext',)
                and node.attr in self.keywords
                and root.parts + (node.attr,) not in self.tainted_attrs
            ):
                return _ImportedFunctionBinding(root.parts, node.attr, 0)
        return _UNKNOWN

    def visit_Call(self, node):
        funcname = self._call_name(node.func)
        if funcname is None:
            yield from self.generic_visit(node)
            return
        if self.analysis_only:
            self.recognized_ids.add(id(node))
            yield from self.generic_visit(node)
            return

        slots = self._slots(node)
        comments = self._comments(node) if self.depth == 0 else []
        lineno = slots[0][0] if slots and slots[0][0] else node.lineno
        self.depth += 1
        try:
            yield from self.generic_visit(node)
        finally:
            self.depth -= 1
        if slots:
            messages = slots[0][1] if len(slots) == 1 else tuple(value for _, value in slots)
            yield lineno, funcname, messages, comments

    def _call_name(self, node):
        if isinstance(node, ast.Name):
            binding = self.resolve(node.id)
            if self._translation(binding, node.id):
                return binding.name if binding.name in self.keywords else node.id
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            binding = self.resolve(node.value.id)
            if (
                isinstance(binding, _ModuleBinding)
                and binding.parts == ('gettext',)
                and node.attr in self.keywords
                and binding.parts + (node.attr,) not in self.tainted_attrs
            ):
                return node.attr
        return None

    def _translation(self, binding, local_name):
        return (
            isinstance(binding, _ImportedFunctionBinding)
            and binding.level == 0
            and binding.module == ('gettext',)
            and (local_name in self.keywords or binding.name in self.keywords)
        )

    def _slots(self, call):
        opening = self.openings.get(id(call))
        if opening is None:
            return []
        from babel.messages.extract import _parse_python_string

        depth = 0
        slots = []
        buffer = []
        current_lineno = None
        fstring = None

        def finish():
            nonlocal buffer, current_lineno
            if buffer:
                slots.append((current_lineno, ''.join(buffer)))
                buffer = []
            else:
                slots.append((current_lineno, None))
            current_lineno = None

        for token in self.tokens[opening + 1:]:
            if token.type == OP and token.string == '(':
                depth += 1
                if depth == 1 and self._recognized_opening(token):
                    finish()
                    break
                continue
            if token.type == OP and token.string == ')':
                if depth == 0:
                    finish()
                    break
                depth -= 1
                continue
            if depth:
                continue
            if token.type == STRING:
                value = _parse_python_string(token.string, self.encoding, self.future_flags)
                if value is not None:
                    if current_lineno is None:
                        current_lineno = token.start[0]
                    buffer.append(value)
            elif FSTRING_START is not None and token.type == FSTRING_START:
                fstring = token.string
                if current_lineno is None:
                    current_lineno = token.start[0]
            elif FSTRING_MIDDLE is not None and token.type == FSTRING_MIDDLE and fstring:
                fstring += token.string
            elif FSTRING_END is not None and token.type == FSTRING_END:
                if fstring is not None:
                    value = _parse_python_string(
                        fstring + token.string, self.encoding, self.future_flags,
                    )
                    if value is not None:
                        buffer.append(value)
                fstring = None
            elif token.type == OP and token.string == ',':
                finish()
            elif token.type != NL and current_lineno is None:
                current_lineno = token.start[0]

            if (
                fstring is not None
                and FSTRING_START is not None
                and token.type not in {FSTRING_START, FSTRING_MIDDLE}
            ):
                fstring = None
        return slots

    def _recognized_opening(self, token):
        return self.opening_by_token.get(
            self.token_positions[token.start],
        ) in self.recognized_ids

    def _comments(self, call):
        if not self.comment_tags:
            return []
        preceding = []
        for line_number in range(call.lineno - 2, -1, -1):
            line = self.lines[line_number].strip()
            if not line.startswith('#'):
                break
            preceding.append(line[1:].strip())
        preceding.reverse()
        comments = []
        for line in preceding:
            if not comments and not any(line.startswith(tag) for tag in self.comment_tags):
                continue
            comments.append(line)
        return comments if any(
            any(line.startswith(tag) for tag in self.comment_tags) for line in comments
        ) else []


def _import_names(node):
    names = set()
    if isinstance(node, ast.Import):
        for alias in node.names:
            names.add(alias.asname or alias.name.split('.')[0])
    else:
        for alias in node.names:
            if alias.name != '*':
                names.add(alias.asname or alias.name)
    return names
