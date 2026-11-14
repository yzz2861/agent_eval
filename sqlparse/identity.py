"""Normalized object identity support for identifiers."""

from sqlparse import sql
from sqlparse import tokens as T

DIALECT_CASEFOLD = {
    "ansi": str.lower,
    "bigquery": str.lower,
    "hive": str.lower,
    "mysql": str.lower,
    "postgresql": str.lower,
    "oracle": str.upper,
    "snowflake": str.upper,
    "sqlite": str.lower,
    "sqlserver": str.lower,
    "access": str.lower,
}

_LEVEL_SEQUENCES = {
    "column": (
        ("column",),
        ("table", "column"),
        ("schema", "table", "column"),
        ("catalog", "schema", "table", "column"),
    ),
    "table": (
        ("table",),
        ("schema", "table"),
        ("catalog", "schema", "table"),
        ("catalog", "schema", "table", "column"),
    ),
}


class ObjectNamePart:
    """One catalog, schema, table, or column part of an object name."""

    __slots__ = (
        "end_position",
        "escape_sequence",
        "escaped",
        "normalized",
        "quote_char",
        "quoted",
        "raw",
        "start_position",
        "value",
    )

    def __init__(self, raw, value, normalized, quoted, quote_char, escaped,
                 escape_sequence, start_position, end_position):
        self.raw = raw
        self.value = value
        self.normalized = normalized
        self.quoted = quoted
        self.quote_char = quote_char
        self.escaped = escaped
        self.escape_sequence = escape_sequence
        self.start_position = start_position
        self.end_position = end_position

    def __repr__(self):
        return f"<ObjectNamePart {self.raw!r}>"

    def __eq__(self, other):
        if not isinstance(other, ObjectNamePart):
            return NotImplemented
        return self.key == other.key

    def __hash__(self):
        return hash(self.key)

    @property
    def key(self):
        if self.quoted:
            return "quoted", self.quote_char, self.value
        return "unquoted", None, self.normalized


class ObjectIdentity:
    """Original and normalized identity information for an identifier."""

    __slots__ = (
        "alias",
        "catalog",
        "column",
        "errors",
        "is_function",
        "kind",
        "parts",
        "schema",
        "table",
    )

    def __init__(self, parts, alias=None, is_function=False, errors=None,
                 kind="table"):
        self.parts = tuple(parts)
        self.alias = alias
        self.is_function = is_function
        self.errors = tuple(errors or ())
        self.kind = kind
        self.catalog = None
        self.schema = None
        self.table = None
        self.column = None

        levels = self._levels_for(len(self.parts), kind)
        for level, part in zip(levels, self.parts, strict=True):
            setattr(self, level, part)

    @staticmethod
    def _levels_for(count, kind):
        if not count:
            return ()
        if count > 4:
            raise ValueError("object names cannot contain more than 4 parts")
        return _LEVEL_SEQUENCES[kind][count - 1]

    def __repr__(self):
        return f"<ObjectIdentity {self.key!r}>"

    def __eq__(self, other):
        if not isinstance(other, ObjectIdentity):
            return NotImplemented
        return (
            self.key == other.key
            and self.is_function == other.is_function
            and self.kind == other.kind
        )

    def __hash__(self):
        return hash((self.key, self.is_function, self.kind))

    @property
    def key(self):
        return tuple(
            ("quoted", part.quote_char, part.value)
            if part.quoted
            else ("unquoted", part.normalized)
            for part in self.parts
        )

    @property
    def key_string(self):
        return ".".join(self._format_key_part(part) for part in self.parts)

    @property
    def valid(self):
        return not self.errors

    @staticmethod
    def _format_key_part(part):
        if not part.quoted:
            return part.normalized
        if part.quote_char == '[':
            return f"[{part.value}]"
        return f"{part.quote_char}{part.value}{part.quote_char}"


def _parse_quoted_name(raw):
    if raw.startswith('['):
        if not raw.endswith(']'):
            return None, None, False, None, "unterminated square bracket quote"
        value = raw[1:-1]
        escaped = ']]' in value
        normalized = value.replace(']]', ']')
        if '[' in normalized:
            return None, None, False, None, "unquoted left square bracket"
        return value, normalized, escaped, ']]' if escaped else None, None

    quote_char = raw[0]
    if quote_char not in ('"', '`', '´') or not raw.endswith(quote_char):
        return None, None, False, None, "unterminated quote"

    value = raw[1:-1]
    if quote_char == '"':
        escaped = '""' in value or '\\"' in value
        normalized = value.replace('""', '"').replace('\\"', '"')
        sequence = '""' if '""' in value else ('\\"' if escaped else None)
    elif quote_char == '`':
        escaped = '``' in value
        normalized = value.replace('``', '`')
        sequence = '``' if escaped else None
    else:
        escaped = '´´' in value
        normalized = value.replace('´´', '´')
        sequence = '´´' if escaped else None
    return value, normalized, escaped, sequence, None


def _name_part(token, casefold):
    raw = token.value
    quoted = raw[:1] in ('"', '`', '´', '[')
    if not quoted:
        normalized = casefold(raw)
        return ObjectNamePart(
            raw=raw,
            value=raw,
            normalized=normalized,
            quoted=False,
            quote_char=None,
            escaped=False,
            escape_sequence=None,
            start_position=0,
            end_position=len(raw),
        ), None

    value, normalized, escaped, escape_sequence, error = _parse_quoted_name(raw)
    if error is not None:
        return None, error
    return ObjectNamePart(
        raw=raw,
        value=value,
        normalized=normalized,
        quoted=True,
        quote_char=raw[0],
        escaped=escaped,
        escape_sequence=escape_sequence,
        start_position=0,
        end_position=len(raw),
    ), None


def _is_inside_function_parenthesis(token):
    parent = token.parent
    while parent is not None:
        if isinstance(parent, sql.Parenthesis):
            grandparent = parent.parent
            if isinstance(grandparent, sql.Function):
                return True
        parent = parent.parent
    return False


def build_object_identity(identifier, strict=False, casefold=None,
                          dialect=None, kind="table"):
    """Build an :class:`ObjectIdentity` from an :class:`sql.Identifier`."""
    if not isinstance(identifier, (sql.Identifier, sql.Function)):
        raise TypeError("expected an sql.Identifier or sql.Function")
    if kind not in _LEVEL_SEQUENCES:
        raise ValueError(f"unsupported identity kind: {kind!r}")
    if casefold is None:
        if dialect is None:
            casefold = str.lower
        elif dialect not in DIALECT_CASEFOLD:
            raise ValueError(f"unsupported dialect: {dialect!r}")
        else:
            casefold = DIALECT_CASEFOLD[dialect]
    elif dialect is not None:
        raise ValueError("casefold and dialect cannot be used together")
    parts = []
    errors = []
    is_function = isinstance(identifier, sql.Function)
    offset = 0

    for token in identifier.flatten():
        if _is_inside_function_parenthesis(token):
            continue
        if token.ttype is T.Error:
            errors.append(f"invalid identifier token: {token.value!r}")

    for idx, token in enumerate(identifier.tokens):
        if token.is_whitespace or isinstance(token, sql.Comment):
            offset += len(token.value)
            continue
        if token.match(T.Keyword, 'AS'):
            offset += len(token.value)
            break
        if isinstance(token, sql.Function):
            is_function = True
            first = token.token_first()
            if isinstance(first, sql.Identifier):
                token = first.token_first()
            else:
                token = first
        if isinstance(token, sql.Identifier) and isinstance(
                identifier, sql.Function) and not parts:
            is_function = True
            token = token.token_first()
        elif isinstance(token, sql.Identifier) and parts:
            previous = identifier.tokens[idx - 1] if idx else None
            if previous is None or not previous.is_whitespace:
                errors.append(f"invalid identifier token: {token.value!r}")
            break
        if isinstance(token, sql.Parenthesis) and parts:
            is_function = True
            offset += len(token.value)
            break
        if isinstance(token, sql.SquareBrackets):
            offset += len(token.value)
            continue
        if token.match(T.Punctuation, '.'):
            offset += len(token.value)
            continue
        if token.ttype is T.Error:
            errors.append(f"invalid identifier token: {token.value!r}")
            offset += len(token.value)
            continue
        if token.ttype not in (T.Name, T.String.Symbol, T.Wildcard,
                               T.Name.Placeholder):
            errors.append(f"invalid identifier token: {token.value!r}")
            offset += len(token.value)
            continue

        part, error = _name_part(token, casefold)
        if error is not None:
            errors.append(f"{error}: {token.value!r}")
        else:
            if len(parts) >= 4:
                errors.append(
                    f"invalid identifier token: {token.value!r}")
                offset += len(token.value)
                continue
            part.start_position = offset
            part.end_position = offset + len(token.value)
            parts.append(part)
        offset += len(token.value)

    identity = ObjectIdentity(
        parts=parts,
        alias=identifier.get_alias(),
        is_function=is_function,
        errors=errors,
        kind=kind,
    )
    if strict and errors:
        raise ValueError("; ".join(errors))
    return identity


def iter_object_identities(statement, strict=False, casefold=None,
                           dialect=None, kind="table"):
    """Yield object identities contained in a statement or token list."""
    invalid_tokens = []
    previous_top_level = None
    for token in statement.flatten():
        if _is_inside_function_parenthesis(token):
            continue
        if token.ttype is T.Error or (
                token.ttype is T.Punctuation and token.value == "[" and
                token.parent is statement and previous_top_level is None):
            invalid_tokens.append(token)
        if token.parent is statement and not token.is_whitespace:
            previous_top_level = token

    if strict and invalid_tokens:
        values = ", ".join(repr(token.value) for token in invalid_tokens)
        raise ValueError(f"invalid identifier token: {values}")

    def walk(token_list):
        for token in token_list.tokens:
            if isinstance(token, (sql.Identifier, sql.Function)):
                yield token
            if isinstance(token, sql.TokenList):
                yield from walk(token)

    for token in walk(statement):
        if isinstance(token, sql.Identifier) and isinstance(
                token.parent, (sql.Identifier, sql.Function)):
            continue
        if isinstance(token, sql.Identifier) and isinstance(
                token.parent, sql.Parenthesis):
            continue
        if isinstance(token, sql.Function) and isinstance(
                token.parent, (sql.Identifier, sql.Function)):
            continue
        if token.ttype is T.Error or (
                token.ttype is T.Punctuation and token.value == "["):
            continue
        identity = build_object_identity(
            token,
            strict=strict,
            casefold=casefold,
            dialect=dialect,
            kind=kind,
        )
        if identity.parts:
            yield identity
