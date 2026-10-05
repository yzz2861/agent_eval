"""
babel.messages.icu
~~~~~~~~~~~~~~~~~~

A small, dependency-free static checker for ICU MessageFormat
patterns (plural, select and selectordinal).

This module deliberately does *not* render messages and has no runtime
dependency on an ICU implementation.  It only parses the pattern syntax
and extracts enough structural information (argument names and argument
kinds) to compare an original message with one of its translations.

The recognized grammar is the ICU MessageFormat pattern syntax::

    message := (text | argument | '#')*
    argument := '{' argName (',' argType (',' argStyle)?)? '}'
    argType := 'plural' | 'select' | 'selectordinal'
             | simpleType
    # plural / selectordinal
    argStyle := offset? (selector '{' message '}')+
    offset := 'offset:' whitespace? integer
    # select
    argStyle := (selector '{' message '}')+
    # simple types (number, date, time, spellout, ...)
    argStyle := arbitrary text without unquoted braces

Quoting follows the ICU "double optional" rules:

* "''" denotes a single literal apostrophe.
* An apostrophe directly preceding '{', '}', '#' or "'" opens a
  quoted section that ends at the next apostrophe; everything inside is
  literal.
* Every other apostrophe is treated as a literal apostrophe.

'#' only has its special "formatted number" meaning inside a
plural/selectordinal branch; anywhere else it is an error.

:copyright: (c) 2013-2026 by the Babel Team.
:license: BSD, see LICENSE for more details.
"""

from __future__ import annotations

from typing import NamedTuple

from babel.messages.catalog import TranslationError

#: Argument kinds used for comparing source and translation.
#:
#: 'simple' means a simple argument without a type, or any of the
#: simple formatter types (number, date ...).  Simple arguments are all
#: mutually compatible.
SIMPLE = 'simple'
PLURAL = 'plural'
SELECT = 'select'
SELECTORDINAL = 'selectordinal'

_COMPLEX_TYPES = frozenset({PLURAL, SELECT, SELECTORDINAL})

#: The CLDR plural keywords accepted by plural and selectordinal.
PLURAL_KEYWORDS = frozenset(
    {'zero', 'one', 'two', 'few', 'many', 'other'},
)

# Characters with a structural meaning in MessageFormat patterns.
_SPECIAL_CHARS = frozenset({'{', '}', '#', "'"})


class IcuLocation(NamedTuple):
    """A position inside an ICU pattern."""

    offset: int
    line: int
    column: int

    def __str__(self) -> str:
        return f'line {self.line}, column {self.column}'


class IcuArgument(NamedTuple):
    """An argument discovered while parsing a pattern."""

    name: str
    kind: str
    path: tuple[str, ...]
    location: IcuLocation


class IcuParseResult(NamedTuple):
    """The information gathered while parsing a pattern."""

    arguments: tuple[IcuArgument, ...]


class IcuSyntaxError(TranslationError):
    """Raised when an ICU pattern cannot be parsed statically."""

    def __init__(
        self,
        message: str,
        location: IcuLocation | None = None,
        path: tuple[str, ...] = (),
    ) -> None:
        suffix_parts = []
        if path:
            suffix_parts.append(f'parameter path: {".".join(path)}')
        if location is not None:
            suffix_parts.append(str(location))
        if suffix_parts:
            message = f'{message} ({", ".join(suffix_parts)})'
        super().__init__(message)
        self.location = location
        self.path = path


def _location(pattern: str, offset: int) -> IcuLocation:
    prefix = pattern[:offset]
    line = prefix.count('\n') + 1
    newline = prefix.rfind('\n')
    column = offset - newline if newline < 0 else offset - newline
    return IcuLocation(offset, line, column)


def parse(pattern: str) -> IcuParseResult:
    """Parse an ICU MessageFormat pattern.

    :param pattern: the pattern text
    :return: an IcuParseResult describing the arguments
    :raises IcuSyntaxError: if the pattern is malformed
    """
    parser = _Parser(pattern)
    return parser.parse()


def compare(
    source: str,
    translation: str,
) -> list[IcuSyntaxError]:
    """Compare an original ICU pattern with its translation.

    Both patterns are parsed statically.  The translation may freely:

    * reorder, repeat or drop placeholders,
    * use different branch texts,
    * add plural categories that make sense for the target language
      (for example add a 'few' branch while the source only has
      'one'/'other'), and
    * omit arguments present in the source.

    It may not:

    * be malformed ICU,
    * reference arguments that do not exist in the source, or
    * use a structurally different kind for an argument (for example
      use 'plural' where the source used 'select').

    :return: a list of IcuSyntaxError objects (empty if compatible)
    """
    errors: list[IcuSyntaxError] = []
    try:
        source_result = parse(source)
    except IcuSyntaxError as exc:
        errors.append(exc)
        source_result = IcuParseResult(())
    try:
        translation_result = parse(translation)
    except IcuSyntaxError as exc:
        errors.append(exc)
        return errors

    source_arguments = {arg.name: arg for arg in source_result.arguments}
    for target_argument in translation_result.arguments:
        source_argument = source_arguments.get(target_argument.name)
        if source_argument is None:
            errors.append(
                IcuSyntaxError(
                    'translation references unknown argument '
                    f'{target_argument.name!r}',
                    target_argument.location,
                    target_argument.path,
                ),
            )
        elif not _kinds_compatible(source_argument.kind, target_argument.kind):
            errors.append(
                IcuSyntaxError(
                    f"argument {target_argument.name!r} has incompatible "
                    f"kind {target_argument.kind!r} in the translation "
                    f"(source uses {source_argument.kind!r})",
                    target_argument.location,
                    target_argument.path,
                ),
            )
    return errors


def _kinds_compatible(source: str, target: str) -> bool:
    if source == SIMPLE or target == SIMPLE:
        return True
    return source == target


class _Parser:
    def __init__(self, pattern: str) -> None:
        self.pattern = pattern
        self.pos = 0
        # Names of the plural/selectordinal arguments that currently
        # enclose the position being parsed, innermost last.
        self._plural_stack: list[str] = []
        # Full parameter path of the argument currently being parsed.
        self._path: tuple[str, ...] = ()
        self._arguments: list[IcuArgument] = []

    # -- low level helpers ------------------------------------------------

    @property
    def eof(self) -> bool:
        return self.pos >= len(self.pattern)

    def error(self, message: str, offset: int | None = None) -> None:
        raise IcuSyntaxError(
            message,
            _location(self.pattern, self.pos if offset is None else offset),
            self._path,
        )

    def skip_ws(self) -> None:
        while not self.eof and self.pattern[self.pos] in ' \t\r\n':
            self.pos += 1

    def read_word(self) -> str:
        start = self.pos
        while not self.eof and self.pattern[self.pos] not in ',{} \t\r\n':
            self.pos += 1
        return self.pattern[start:self.pos]

    def expect(self, char: str) -> None:
        if self.eof or self.pattern[self.pos] != char:
            self.error(f'expected {char!r}')
        self.pos += 1

    def skip_quoted(self) -> bool:
        """Skip a quoted section if the parser is positioned at one.

        Returns True if a quoted section (or a doubled apostrophe) was
        consumed.
        """
        if self.eof or self.pattern[self.pos] != "'":
            return False
        if self.pos + 1 < len(self.pattern) and self.pattern[self.pos + 1] == "'":
            # Doubled apostrophe -> literal apostrophe.
            self.pos += 2
            return True
        if (
            self.pos + 1 < len(self.pattern)
            and self.pattern[self.pos + 1] in _SPECIAL_CHARS
        ):
            # Opening apostrophe of a quoted section.
            end = self.pattern.find("'", self.pos + 2)
            if end < 0:
                self.error("unterminated quoted section (missing closing apostrophe)")
            self.pos = end + 1
            return True
        # A standalone apostrophe before a non-special character is literal.
        return False

    # -- grammar -----------------------------------------------------------

    def parse(self) -> IcuParseResult:
        self._parse_message(enclosed=False)
        return IcuParseResult(tuple(self._arguments))

    def _parse_message(self, enclosed: bool) -> None:
        while not self.eof:
            char = self.pattern[self.pos]
            if char == '}':
                if enclosed:
                    return
                self.error("unexpected '}' without matching '{'")
            if self.skip_quoted():
                continue
            if char == "'":
                # A literal apostrophe before a non-special character.
                self.pos += 1
                continue
            if char == '#':
                if not self._plural_stack:
                    self.error(
                        "'#' is only allowed inside a 'plural' or "
                        "'selectordinal' branch",
                    )
                self.pos += 1
                continue
            if char == '{':
                self._parse_argument()
                continue
            self.pos += 1

    def _parse_argument(self) -> None:
        open_pos = self.pos
        self.expect('{')
        self.skip_ws()
        name_start = self.pos
        name = self.read_word()
        if not name:
            self.error('missing argument name', name_start)
        for invalid_char in ("'", '#', '{', '}'):
            if invalid_char in name:
                self.error(f'invalid argument name {name!r}', name_start)
        self.skip_ws()

        if self.eof:
            self.error("unclosed argument (missing '}')", open_pos)

        if self.pattern[self.pos] == '}':
            self.pos += 1
            self._register(name, SIMPLE, name_start)
            return

        self.expect(',')
        self.skip_ws()
        type_start = self.pos
        arg_type = self.read_word()
        if not arg_type:
            self.error('missing argument type', type_start)
        for invalid_char in ("'", '#', '{', '}'):
            if invalid_char in arg_type:
                self.error(f'invalid argument type {arg_type!r}', type_start)
        self.skip_ws()

        if self.eof:
            self.error("unclosed argument (missing '}')", open_pos)

        outer_path = self._path
        if arg_type in _COMPLEX_TYPES:
            self._path = outer_path + (name,)
            self._register(name, arg_type, name_start)
            if self.pattern[self.pos] != ',':
                self.error(f"expected ',' after argument type {arg_type!r}")
            self.pos += 1
            self._parse_complex_style(arg_type, open_pos, name)
            self._path = outer_path
        else:
            self._register(name, SIMPLE, name_start)
            self._parse_simple_style(open_pos)

    def _register(self, name: str, kind: str, offset: int) -> None:
        for argument in self._arguments:
            if argument.name != name:
                continue
            if not _kinds_compatible(argument.kind, kind):
                raise IcuSyntaxError(
                    f"argument {name!r} used with conflicting types "
                    f"{argument.kind!r} and {kind!r}",
                    _location(self.pattern, offset),
                    self._path,
                )
            return
        self._arguments.append(
            IcuArgument(name, kind, self._path, _location(self.pattern, offset)),
        )

    def _parse_simple_style(self, open_pos: int) -> None:
        # The style of a simple argument is opaque text.  Only structural
        # characters matter: quotes must balance and unquoted braces are
        # illegal (nested arguments are not allowed in simple styles).
        while not self.eof:
            char = self.pattern[self.pos]
            if self.skip_quoted():
                continue
            if char == "'":
                self.pos += 1
                continue
            if char == '{':
                self.error('unexpected nested argument in simple argument style')
            if char == '}':
                self.pos += 1
                return
            self.pos += 1
        self.error("unclosed argument (missing '}')", open_pos)

    def _parse_complex_style(self, arg_type: str, open_pos: int, name: str) -> None:
        if arg_type in (PLURAL, SELECTORDINAL):
            self._plural_stack.append(name)
            try:
                self._parse_choices(arg_type, open_pos, allow_offset=True)
            finally:
                self._plural_stack.pop()
        else:
            self._parse_choices(arg_type, open_pos, allow_offset=False)

    def _parse_choices(self, arg_type: str, open_pos: int, allow_offset: bool) -> None:
        seen_selectors: set[str] = set()
        seen_real_selector = False
        seen_offset = False
        while True:
            self.skip_ws()
            if self.eof or self.pattern[self.pos] == '}':
                break
            selector_pos = self.pos
            selector = self.read_word()
            if not selector:
                self.error('missing selector', selector_pos)

            if selector == 'offset:':
                if not allow_offset:
                    self.error("'offset:' is only valid for plural arguments")
                if seen_offset:
                    self.error("duplicate 'offset:' declaration")
                if seen_real_selector:
                    self.error("'offset:' must precede all plural selectors")
                seen_offset = True
                self.skip_ws()
                number_start = self.pos
                number = self.read_word()
                if not _is_offset_value(number):
                    self.error(f'invalid offset value {number!r}', number_start)
                continue
            offset_value = _offset_value(selector)
            if offset_value is not None:
                if not allow_offset:
                    self.error("'offset:' is only valid for plural arguments")
                if seen_offset:
                    self.error("duplicate 'offset:' declaration")
                if seen_real_selector:
                    self.error("'offset:' must precede all plural selectors")
                seen_offset = True
                if not _is_offset_value(offset_value):
                    self.error(f'invalid offset value {offset_value!r}', selector_pos)
                continue

            seen_real_selector = True
            self._validate_selector(arg_type, selector, selector_pos)
            if selector in seen_selectors:
                self.error(f'duplicate selector {selector!r}', selector_pos)
            seen_selectors.add(selector)

            self.skip_ws()
            if self.eof or self.pattern[self.pos] != '{':
                self.error(f"expected '{{' after selector {selector!r}")
            outer_path = self._path
            self._path = outer_path + (selector,)
            self.pos += 1  # consume '{'
            self._parse_message(enclosed=True)
            if self.eof:
                self.error("unclosed branch (missing '}')", open_pos)
            self.expect('}')
            self._path = outer_path

        if self.eof:
            self.error("unclosed argument (missing '}')", open_pos)
        self.pos += 1  # consume '}'

        if not seen_real_selector:
            self.error(
                f"the {arg_type!r} argument requires at least one branch",
                open_pos,
            )
        if 'other' not in seen_selectors:
            self.error(
                f"the {arg_type!r} argument requires an 'other' branch",
                open_pos,
            )

    def _validate_selector(self, arg_type: str, selector: str, offset: int) -> None:
        if arg_type == SELECT:
            if '#' in selector or "'" in selector or selector == 'offset:':
                self.error(f'invalid select selector {selector!r}', offset)
            return
        if selector.startswith('='):
            value = selector[1:]
            if not value or not value.lstrip('-').isdigit():
                self.error(f'invalid explicit plural selector {selector!r}', offset)
            return
        if selector not in PLURAL_KEYWORDS:
            self.error(
                f'invalid plural keyword {selector!r} '
                f'(expected one of {sorted(PLURAL_KEYWORDS)} or =<number>)',
                offset,
            )


def _is_offset_value(value: str) -> bool:
    if not value:
        return False
    return value.lstrip('-').isdigit()


def _offset_value(word: str) -> str | None:
    """Return the integer of an 'offset:N' selector, or None.

    A bare 'offset:' (value separated by whitespace) is handled by the
    caller and returns None here.
    """
    if not word.startswith('offset:') or word == 'offset:':
        return None
    return word[len('offset:'):]
