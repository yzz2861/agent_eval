"""Static validation helpers for ICU MessageFormat strings."""

from __future__ import annotations

from dataclasses import dataclass, field

from babel.messages.catalog import TranslationError

__all__ = ['ICUFormatError', 'parse_message', 'validate_translation']

PLURAL_TAGS = frozenset({'zero', 'one', 'two', 'few', 'many', 'other'})
COMPLEX_TYPES = frozenset({'plural', 'selectordinal', 'select'})


class ICUFormatError(TranslationError):
    """An error in an ICU MessageFormat string."""

    def __init__(
        self,
        message: str,
        *,
        path: tuple[str, ...] = (),
        position: int | None = None,
    ) -> None:
        self.message = message
        self.path = path
        self.position = position
        super().__init__(message)


@dataclass
class MessageNode:
    arguments: dict[tuple[str, ...], ArgumentNode] = field(default_factory=dict)
    plurals: dict[tuple[str, ...], PluralNode] = field(default_factory=dict)


@dataclass
class PluralNode:
    types: set[str]
    position: int
    offset: int | None = None
    branch_positions: dict[str, int] = field(default_factory=dict)
    branches: dict[str, MessageNode] = field(default_factory=dict)


@dataclass
class ArgumentNode:
    name: str
    type: str | None
    position: int


def format_error(error: ICUFormatError, text: str, label: str) -> str:
    line = text.count('\n', 0, error.position) + 1 if error.position is not None else 1
    if error.position is None:
        column = 1
    else:
        last_newline = text.rfind('\n', 0, error.position)
        column = error.position + 1 if last_newline < 0 else error.position - last_newline
    path = '.'.join(error.path) if error.path else '<root>'
    return f'{label}: {error.message} (at {path}, line {line}, column {column})'


@dataclass
class _Parser:
    text: str
    pos: int = 0

    def error(
        self,
        message: str,
        *,
        path: tuple[str, ...] = (),
        pos: int | None = None,
    ) -> ICUFormatError:
        return ICUFormatError(message, path=path, position=self.pos if pos is None else pos)

    def skip_ws(self) -> None:
        while self.pos < len(self.text) and self.text[self.pos].isspace():
            self.pos += 1

    def peek(self) -> str:
        return self.text[self.pos] if self.pos < len(self.text) else ''

    def consume_quoted(self, quote_pos: int) -> None:
        self.pos = quote_pos + 1
        while self.pos < len(self.text):
            ch = self.text[self.pos]
            if ch == "'":
                if self.pos + 1 < len(self.text) and self.text[self.pos + 1] == "'":
                    self.pos += 2
                    continue
                self.pos += 1
                return
            self.pos += 1
        raise self.error('Unterminated quoted string', pos=quote_pos)

    def is_quote_start(self, quote_hash: bool = False) -> bool:
        if self.peek() != "'":
            return False
        next_ch = self.text[self.pos + 1] if self.pos + 1 < len(self.text) else ''
        quoted_characters = "{}'" + ('#' if quote_hash else '')
        return next_ch in quoted_characters or next_ch == ''

    def parse_message(
        self,
        path: tuple[str, ...] = (),
        *,
        plural_name: str | None = None,
        terminator: str | None = None,
    ) -> MessageNode:
        node = MessageNode()
        start = self.pos

        while self.pos < len(self.text):
            ch = self.text[self.pos]
            if terminator is not None and ch == terminator:
                return node
            if ch == "'" and self.is_quote_start(plural_name is not None):
                self.consume_quoted(self.pos)
                continue
            if ch == "'":
                self.pos += 1
                continue
            if ch == '}':
                raise self.error('Unexpected closing brace', path=path)
            if ch == '#' and plural_name is not None:
                self.pos += 1
                continue
            if ch == '{':
                argument_name, argument_type, argument_pos, plural_node = self.parse_argument(
                    path,
                    plural_name=plural_name,
                )
                argument_path = path + (argument_name,)
                node.arguments[argument_path] = ArgumentNode(
                    name=argument_name,
                    type=argument_type,
                    position=argument_pos,
                )
                if plural_node is not None:
                    node.plurals[argument_path] = plural_node
                continue
            self.pos += 1

        if terminator is not None:
            raise self.error('Expected closing brace', path=path, pos=start)
        return node

    def parse_argument(
        self,
        path: tuple[str, ...],
        *,
        plural_name: str | None,
    ) -> tuple[str, str | None, int, PluralNode | None]:
        start = self.pos
        self.pos += 1
        self.skip_ws()
        name_start = self.pos
        while self.pos < len(self.text) and (
            self.text[self.pos].isalnum() or self.text[self.pos] == '_'
        ):
            self.pos += 1
        name = self.text[name_start:self.pos]
        if not name:
            raise self.error('Missing argument name', path=path, pos=start)
        self.skip_ws()
        argument_path = path + (name,)

        if self.peek() == '}':
            self.pos += 1
            return name, None, start, None
        if self.peek() == '':
            raise self.error('Expected closing brace', path=argument_path)
        if self.peek() != ',':
            raise self.error('Expected comma or closing brace', path=argument_path)

        self.pos += 1
        self.skip_ws()
        type_start = self.pos
        while self.pos < len(self.text):
            ch = self.text[self.pos]
            if ch.isspace() or ch in ',}':
                break
            self.pos += 1
        argument_type = self.text[type_start:self.pos]
        if not argument_type:
            raise self.error('Missing argument type', path=argument_path, pos=type_start)
        self.skip_ws()

        if argument_type in COMPLEX_TYPES:
            if self.peek() != ',':
                raise self.error('Expected comma after complex argument type', path=argument_path)
            self.pos += 1
            plural_node = self.parse_complex_body(name, argument_type, argument_path, plural_name)
            self.skip_ws()
            if self.peek() != '}':
                raise self.error('Expected closing brace', path=argument_path)
            self.pos += 1
            return name, argument_type, start, plural_node

        if self.peek() == '}':
            self.pos += 1
            return name, argument_type, start, None
        if self.peek() == '':
            raise self.error('Expected closing brace', path=argument_path)
        if self.peek() != ',':
            raise self.error('Expected comma or closing brace', path=argument_path)

        self.pos += 1
        style_start = self.pos
        style = self.parse_simple_style(argument_path)
        if not style.strip():
            raise self.error('Missing argument style', path=argument_path, pos=style_start)
        self.skip_ws()
        if self.peek() != '}':
            raise self.error('Expected closing brace', path=argument_path)
        self.pos += 1
        return name, argument_type, start, None

    def parse_simple_style(self, path: tuple[str, ...]) -> str:
        start = self.pos
        depth = 0
        while self.pos < len(self.text):
            ch = self.text[self.pos]
            if ch == "'" and self.is_quote_start():
                self.consume_quoted(self.pos)
                continue
            if ch == '{':
                if depth == 0:
                    raise self.error('Unexpected opening brace in argument style', path=path)
                depth += 1
            elif ch == '}':
                if depth == 0:
                    return self.text[start:self.pos]
                depth -= 1
            self.pos += 1
        raise self.error('Expected closing brace', path=path, pos=start)

    def parse_complex_body(
        self,
        name: str,
        argument_type: str,
        path: tuple[str, ...],
        parent_plural_name: str | None,
    ) -> PluralNode:
        node = PluralNode(types={argument_type}, position=self.pos)
        seen: set[str] = set()
        child_plural_name = name if argument_type in {'plural', 'selectordinal'} else parent_plural_name

        while True:
            self.skip_ws()
            if self.peek() == '}':
                if 'other' not in seen:
                    raise self.error("Missing required 'other' branch", path=path)
                return node

            if argument_type == 'plural' and self._peek_keyword('offset'):
                self._parse_offset(path, node)
                continue

            selector_start = self.pos
            while self.pos < len(self.text) and not (
                self.text[self.pos].isspace() or self.text[self.pos] == '{'
            ):
                self.pos += 1
            selector = self.text[selector_start:self.pos]
            branch_path = path + (selector,)
            if not selector:
                message = "Missing required 'other' branch" if self.peek() == '' else 'Missing plural or select branch'
                raise self.error(message, path=path, pos=selector_start)
            self._validate_selector(argument_type, selector, branch_path, selector_start)
            if selector in seen:
                raise self.error(f'Duplicate branch {selector!r}', path=branch_path, pos=selector_start)
            seen.add(selector)
            node.branch_positions[selector] = selector_start

            self.skip_ws()
            if self.peek() != '{':
                raise self.error('Expected branch body', path=branch_path)
            self.pos += 1
            branch = self.parse_message(
                branch_path,
                plural_name=child_plural_name,
                terminator='}',
            )
            if self.peek() != '}':
                raise self.error('Expected closing brace', path=path)
            self.pos += 1
            node.branches[selector] = branch

    def _peek_keyword(self, keyword: str) -> bool:
        end = self.pos + len(keyword)
        if self.text[self.pos:end] != keyword:
            return False
        if end >= len(self.text):
            return True
        return self.text[end].isspace() or self.text[end] == ':'

    def _parse_offset(self, path: tuple[str, ...], node: PluralNode) -> None:
        offset_pos = self.pos
        self.pos += len('offset')
        self.skip_ws()
        if self.peek() != ':':
            raise self.error('Expected colon after offset', path=path)
        self.pos += 1
        self.skip_ws()
        value_start = self.pos
        if self.peek() in '+-':
            self.pos += 1
        digits_start = self.pos
        while self.pos < len(self.text) and self.text[self.pos].isdigit():
            self.pos += 1
        if self.pos == digits_start:
            raise self.error('Invalid plural offset', path=path, pos=value_start)
        if node.offset is not None:
            raise self.error('Duplicate plural offset', path=path, pos=offset_pos)
        node.offset = int(self.text[value_start:self.pos])

    def _validate_selector(
        self,
        argument_type: str,
        selector: str,
        path: tuple[str, ...],
        pos: int,
    ) -> None:
        if argument_type == 'select':
            if selector == 'offset' or not all(ch.isalnum() or ch in '_-' for ch in selector):
                raise self.error(f'Invalid select branch {selector!r}', path=path, pos=pos)
            return
        if selector in PLURAL_TAGS:
            return
        if re_match_exact_number(selector):
            return
        if selector[0].isalpha() or selector[0] == '_':
            return
        raise self.error(f'Invalid plural branch {selector!r}', path=path, pos=pos)


def re_match_exact_number(selector: str) -> bool:
    if not selector.startswith('=') or len(selector) < 2:
        return False
    value = selector[1:]
    return value.isdigit()


def parse_message(text: str) -> MessageNode:
    return _Parser(text).parse_message()


def validate_translation(
    original: str,
    translation: str,
    *,
    plural_categories: frozenset[str] | set[str] | None = None,
    ordinal_categories: frozenset[str] | set[str] | None = None,
) -> None:
    source = parse_message(original)
    target = parse_message(translation)
    validate_nodes(
        source,
        target,
        plural_categories=plural_categories,
        ordinal_categories=ordinal_categories,
    )


def validate_nodes(
    source: MessageNode,
    target: MessageNode,
    *,
    plural_categories: frozenset[str] | set[str] | None = None,
    ordinal_categories: frozenset[str] | set[str] | None = None,
) -> None:
    allowed_plural = frozenset(plural_categories) if plural_categories is not None else PLURAL_TAGS
    allowed_ordinal = (
        frozenset(ordinal_categories) if ordinal_categories is not None else PLURAL_TAGS
    )
    source_arguments = _collect_arguments(source)
    target_arguments = _collect_arguments(target)

    for name, occurrences in target_arguments.items():
        target_types = {occurrence.type for occurrence in occurrences}
        if len(target_types) > 1:
            occurrence = occurrences[0]
            raise ICUFormatError(
                f'Conflicting argument types for {name!r}',
                path=occurrence.path,
                position=occurrence.position,
            )
        target_type = next(iter(target_types))
        source_occurrences = source_arguments.get(name)
        if not source_occurrences:
            occurrence = occurrences[0]
            raise ICUFormatError(
                f'Unknown argument {name!r}',
                path=occurrence.path,
                position=occurrence.position,
            )
        source_types = {occurrence.type for occurrence in source_occurrences}
        if len(source_types) > 1:
            occurrence = source_occurrences[0]
            raise ICUFormatError(
                f'Conflicting argument types for {name!r}',
                path=occurrence.path,
                position=occurrence.position,
            )
        source_type = next(iter(source_types))
        if target_type != source_type:
            source_label = source_type or 'simple'
            target_label = target_type or 'simple'
            occurrence = occurrences[0]
            raise ICUFormatError(
                f'Incompatible argument type for {name!r}: '
                f'expected {source_label}, got {target_label}',
                path=occurrence.path,
                position=occurrence.position,
            )

    _validate_plural_branches(
        source,
        target,
        allowed_plural=allowed_plural | {'other'},
        allowed_ordinal=allowed_ordinal | {'other'},
    )


@dataclass
class _ArgumentOccurrence:
    type: str | None
    path: tuple[str, ...]
    position: int


def _collect_arguments(node: MessageNode) -> dict[str, list[_ArgumentOccurrence]]:
    result: dict[str, list[_ArgumentOccurrence]] = {}
    _collect_arguments_from(node, result)
    return result


def _collect_arguments_from(
    node: MessageNode,
    result: dict[str, list[_ArgumentOccurrence]],
) -> None:
    for path, argument in node.arguments.items():
        result.setdefault(argument.name, []).append(
            _ArgumentOccurrence(type=argument.type, path=path, position=argument.position),
        )
    for plural in node.plurals.values():
        for branch in plural.branches.values():
            _collect_arguments_from(branch, result)


def _validate_plural_branches(
    source: MessageNode,
    target: MessageNode,
    *,
    allowed_plural: frozenset[str],
    allowed_ordinal: frozenset[str],
) -> None:
    source_plurals = _collect_plurals(source)
    target_plurals = _collect_plurals(target)

    for name, target_occurrences in target_plurals.items():
        source_occurrences = source_plurals.get(name)
        if not source_occurrences:
            continue
        source_types = {next(iter(occurrence.node.types)) for occurrence in source_occurrences}
        target_types = {next(iter(occurrence.node.types)) for occurrence in target_occurrences}
        if len(source_types) > 1 or len(target_types) > 1:
            occurrence = target_occurrences[0]
            raise ICUFormatError('Conflicting complex argument types', path=occurrence.path)
        source_type = next(iter(source_types))
        target_type = next(iter(target_types))
        if source_type != target_type:
            occurrence = target_occurrences[0]
            raise ICUFormatError(
                f'Incompatible argument type for {name!r}: '
                f'expected {source_type}, got {target_type}',
                path=occurrence.path,
                position=occurrence.node.position,
            )

        source_selectors: set[str] = set()
        for occurrence in source_occurrences:
            source_selectors.update(occurrence.node.branches)
        allowed = (
            allowed_plural if target_type == 'plural' else
            allowed_ordinal if target_type == 'selectordinal' else
            frozenset(source_selectors)
        )
        for occurrence in target_occurrences:
            for selector in occurrence.node.branches:
                if selector in source_selectors or selector in allowed:
                    continue
                raise ICUFormatError(
                    f'Unknown branch {selector!r}',
                    path=occurrence.path + (selector,),
                    position=occurrence.node.branch_positions[selector],
                )


@dataclass
class _PluralOccurrence:
    node: PluralNode
    path: tuple[str, ...]


def _collect_plurals(node: MessageNode) -> dict[str, list[_PluralOccurrence]]:
    result: dict[str, list[_PluralOccurrence]] = {}
    _collect_plurals_from(node, (), result)
    return result


def _collect_plurals_from(
    node: MessageNode,
    prefix: tuple[str, ...],
    result: dict[str, list[_PluralOccurrence]],
) -> None:
    for path, plural in node.plurals.items():
        full_path = prefix + path
        result.setdefault(path[-1], []).append(_PluralOccurrence(node=plural, path=full_path))
        for selector, branch in plural.branches.items():
            _collect_plurals_from(branch, full_path + (selector,), result)
