# mypy: allow-untyped-defs, allow-incomplete-defs, allow-untyped-calls
# mypy: no-warn-return-any, allow-any-generics

"""Interpret and rewrite SQLite CREATE TRIGGER statements.

This is used by the SQLite batch "move and copy" table recreate to
carry trigger definitions over to the new table.  The rewrite is
token-based so that string literals, comments, and similarly-named
identifiers are never modified by accident.

"""

from __future__ import annotations

from collections.abc import Collection
from collections.abc import Mapping
import re
from typing import NamedTuple

from ..util import exc

_BACKTICK = "\x60"


class TriggerRewriteError(exc.CommandError):
    """A trigger definition cannot be reliably carried over to the
    table recreated by a batch migration.

    This is always a migration-authoring problem, not a runtime one.

    """


class _Token(NamedTuple):
    kind: str  # ws, comment, string, qident, ident, number, punct
    text: str


_TOKENIZER = re.compile(
    r"""
      (?P<ws>\s+)
    | (?P<comment>--[^\n]*|/\*.*?\*/)
    | (?P<string>'(?:[^']|'')*')
    | (?P<qident>"(?:[^"]|"")*"|\x60(?:[^\x60]|\x60\x60)*\x60|\[[^\]]*\])
    | (?P<number>\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)
    | (?P<ident>[A-Za-z_\u0080-\uffff][A-Za-z0-9_$\u0080-\uffff]*)
    | (?P<punct>.)
    """,
    re.VERBOSE | re.DOTALL,
)

_BARE_IDENT = re.compile(
    r"[A-Za-z_\u0080-\uffff][A-Za-z0-9_$\u0080-\uffff]*\Z"
)

# keywords that may appear in a trigger WHEN clause / expression and
# therefore must not be mistaken for column references
_EXPRESSION_KEYWORDS = frozenset("""
    AND OR NOT NULL IS IN LIKE GLOB REGEXP MATCH BETWEEN CASE WHEN THEN
    ELSE END EXISTS SELECT AS COLLATE ESCAPE TRUE FALSE ISNULL NOTNULL
    CURRENT_DATE CURRENT_TIME CURRENT_TIMESTAMP
    """.split())

# fuller keyword list, used to decide if an identifier is safe to emit
# without quotes
_SQLITE_KEYWORDS = frozenset("""
    ABORT ACTION ADD AFTER ALL ALTER ALWAYS ANALYZE AND AS ASC ATTACH
    AUTOINCREMENT BEFORE BEGIN BETWEEN BY CASCADE CASE CAST CHECK COLLATE
    COLUMN COMMIT CONFLICT CONSTRAINT CREATE CROSS CURRENT CURRENT_DATE
    CURRENT_TIME CURRENT_TIMESTAMP CURRENT_USER DATABASE DEFAULT
    DEFERRABLE DEFERRED DELETE DESC DETACH DISTINCT DO DROP EACH ELSE END
    ESCAPE EXCEPT EXCLUDE EXCLUSIVE EXISTS EXPLAIN FAIL FILTER FIRST
    FOLLOWING FOR FOREIGN FROM FULL GENERATED GLOB GROUP GROUPS HAVING IF
    IGNORE IMMEDIATE IN INDEX INDEXED INITIALLY INNER INSERT INSTEAD
    INTERSECT INTO IS ISNULL JOIN KEY LAST LEFT LIKE LIMIT MATCH
    MATERIALIZED NATURAL NEW NO NOT NOTHING NOTNULL NULL NULLS OF OFFSET
    OLD ON OR ORDER OTHERS OUTER OVER PARTITION PLAN PRAGMA PRECEDING
    PRIMARY QUERY RAISE RANGE RECURSIVE REFERENCES REGEXP REINDEX RELEASE
    RENAME REPLACE RESTRICT RETURNING RIGHT ROLLBACK ROW ROWS SAVEPOINT
    SCHEMA SELECT SET TABLE TEMP TEMPORARY THEN TIES TO TRANSACTION
    TRIGGER UNBOUNDED UNION UNIQUE UPDATE USING VACUUM VALUES VIEW
    VIRTUAL WHEN WHERE WINDOW WITH WITHOUT
    """.split())

# statement-leading keywords after which an identifier that matches the
# renamed table is a reference to that table
_TABLE_REF_LEADERS = frozenset(
    ("UPDATE", "INTO", "FROM", "JOIN", "IGNORE", "REPLACE")
)


def _tokenize(sql: str) -> list[_Token]:
    tokens = []
    pos = 0
    for match in _TOKENIZER.finditer(sql):
        if match.start() != pos:  # pragma: no cover - defensive
            raise TriggerRewriteError(
                "could not tokenize trigger definition at offset %d" % pos
            )
        tokens.append(
            _Token(match.lastgroup, match.group())  # type: ignore[arg-type]
        )
        pos = match.end()
    return tokens


def _ident_value(token: _Token) -> str:
    """Return the identifier referred to by an ident/qident token."""
    text = token.text
    if token.kind == "ident":
        return text
    assert token.kind == "qident"
    if text.startswith('"'):
        return text[1:-1].replace('""', '"')
    elif text.startswith(_BACKTICK):
        return text[1:-1].replace(_BACKTICK * 2, _BACKTICK)
    else:  # [name]
        return text[1:-1]


def _render_identifier(name: str, like: _Token | None = None) -> str:
    """Render an identifier, preserving the quoting style of the
    token it replaces when there is one."""
    if like is not None and like.kind == "qident":
        if like.text.startswith('"'):
            return '"%s"' % name.replace('"', '""')
        elif like.text.startswith(_BACKTICK):
            return "{0}{1}{0}".format(
                _BACKTICK, name.replace(_BACKTICK, _BACKTICK * 2)
            )
        else:
            return "[%s]" % name
    if _BARE_IDENT.match(name) and name.upper() not in _SQLITE_KEYWORDS:
        return name
    return '"%s"' % name.replace('"', '""')


class _ParseState:
    """Cursor over significant (non-whitespace, non-comment) tokens."""

    def __init__(self, tokens: list[_Token], sig: list[int]) -> None:
        self.tokens = tokens
        self.sig = sig
        self.pos = 0

    @property
    def current(self) -> _Token | None:
        if self.pos < len(self.sig):
            return self.tokens[self.sig[self.pos]]
        return None

    def at_keyword(self, *words: str) -> bool:
        tok = self.current
        return (
            tok is not None
            and tok.kind == "ident"
            and tok.text.upper() in words
        )

    def at_ident(self) -> bool:
        tok = self.current
        return tok is not None and tok.kind in ("ident", "qident")

    def at_punct(self, char: str) -> bool:
        tok = self.current
        return tok is not None and tok.kind == "punct" and tok.text == char


def rewrite_trigger_sql(
    sql: str,
    *,
    trigger_name: str,
    table_name: str,
    new_table_name: str | None = None,
    column_renames: Mapping[str, str] | None = None,
    dropped_columns: Collection[str] = (),
) -> str:
    """Return a rewritten version of a SQLite CREATE TRIGGER
    statement, adjusted for a table and/or column rename.

    :param sql: the original CREATE TRIGGER statement.
    :param trigger_name: name of the trigger, used in error messages.
    :param table_name: name of the table the trigger is defined on.
    :param new_table_name: new name for the table, if the batch
     operation renames it.
    :param column_renames: mapping of old to new column names.
    :param dropped_columns: names of columns dropped by the batch
     operation; a trigger that references one of these cannot be
     preserved.

    :raises TriggerRewriteError: if the statement cannot be reliably
     interpreted, or if it references a dropped column.

    """
    tokens = _tokenize(sql)
    sig = [
        index
        for index, tok in enumerate(tokens)
        if tok.kind not in ("ws", "comment")
    ]

    def fail(reason: str) -> None:
        raise TriggerRewriteError(
            "Cannot reliably interpret the definition of trigger "
            f"'{trigger_name}' on table '{table_name}' in order to "
            f"preserve it across a batch table recreate ({reason}). "
            "To migrate this trigger, drop it before the batch "
            "operation and recreate it afterwards, or don't use "
            "preserve_triggers."
        )

    if not sig:
        fail("no statement found")

    st = _ParseState(tokens, sig)

    if not st.at_keyword("CREATE"):
        fail("expected CREATE")
    st.pos += 1
    if st.at_keyword("TEMP", "TEMPORARY"):
        st.pos += 1
    if not st.at_keyword("TRIGGER"):
        fail("expected TRIGGER")
    st.pos += 1
    if st.at_keyword("IF"):
        st.pos += 1
        if not st.at_keyword("NOT"):
            fail("expected NOT after IF")
        st.pos += 1
        if not st.at_keyword("EXISTS"):
            fail("expected EXISTS after IF NOT")
        st.pos += 1

    # [schema.]trigger-name
    if not st.at_ident():
        fail("expected trigger name")
    st.pos += 1
    if st.at_punct("."):
        st.pos += 1
        if not st.at_ident():
            fail("expected trigger name after schema qualifier")
        st.pos += 1

    if st.at_keyword("BEFORE", "AFTER"):
        st.pos += 1
    elif st.at_keyword("INSTEAD"):
        st.pos += 1
        if not st.at_keyword("OF"):
            fail("expected OF after INSTEAD")
        st.pos += 1

    column_refs: list[int] = []  # token indexes of column references

    if st.at_keyword("DELETE", "INSERT"):
        st.pos += 1
    elif st.at_keyword("UPDATE"):
        st.pos += 1
        if st.at_keyword("OF"):
            st.pos += 1
            while True:
                if not st.at_ident():
                    fail("expected column name in UPDATE OF clause")
                column_refs.append(st.sig[st.pos])
                st.pos += 1
                if st.at_punct(","):
                    st.pos += 1
                else:
                    break
    else:
        fail("expected DELETE, INSERT or UPDATE")

    if not st.at_keyword("ON"):
        fail("expected ON")
    st.pos += 1
    if not st.at_ident():
        fail("expected table name after ON")
    on_table_index = st.sig[st.pos]
    st.pos += 1
    if st.at_punct("."):
        st.pos += 1
        if not st.at_ident():
            fail("expected table name after schema qualifier")
        on_table_index = st.sig[st.pos]
        st.pos += 1

    if _ident_value(tokens[on_table_index]).lower() != table_name.lower():
        fail(
            "trigger is defined on table "
            f"'{_ident_value(tokens[on_table_index])}', not "
            f"'{table_name}'"
        )

    if st.at_keyword("FOR"):
        st.pos += 1
        if not st.at_keyword("EACH"):
            fail("expected EACH after FOR")
        st.pos += 1
        if not st.at_keyword("ROW"):
            fail("expected ROW after FOR EACH")
        st.pos += 1

    when_region: tuple[int, int] | None = None
    if st.at_keyword("WHEN"):
        st.pos += 1
        when_start = st.pos
        depth = 0
        while True:
            tok = st.current
            if tok is None:
                fail("expected BEGIN")
            if tok.kind == "punct":
                if tok.text == "(":
                    depth += 1
                elif tok.text == ")":
                    depth -= 1
                    if depth < 0:
                        fail("unbalanced parentheses in WHEN clause")
            elif depth == 0 and st.at_keyword("BEGIN"):
                break
            st.pos += 1
        when_region = (when_start, st.pos)

    if not st.at_keyword("BEGIN"):
        fail("expected BEGIN")
    st.pos += 1
    body_start = st.pos

    # the trigger body runs up to the final END keyword, which may be
    # followed by a single optional semicolon and nothing else
    end_pos = len(sig) - 1
    if (
        tokens[sig[end_pos]].kind == "punct"
        and tokens[sig[end_pos]].text == ";"
    ):
        end_pos -= 1
    end_token = tokens[sig[end_pos]]
    if not (end_token.kind == "ident" and end_token.text.upper() == "END"):
        fail("expected END at the end of the trigger definition")
    for trailing in sig[end_pos + 1 :]:
        tok = tokens[trailing]
        if not (tok.kind == "punct" and tok.text == ";"):
            fail("unexpected tokens after END")
    if end_pos <= body_start:
        fail("trigger body is empty")

    # OLD.column / NEW.column references, valid both in the WHEN clause
    # and in the trigger body
    index = when_region[0] if when_region is not None else body_start
    while index < end_pos - 1:
        tok = tokens[sig[index]]
        if tok.kind == "ident" and tok.text.upper() in ("OLD", "NEW"):
            dot = tokens[sig[index + 1]]
            col = tokens[sig[index + 2]]
            if (
                dot.kind == "punct"
                and dot.text == "."
                and col.kind in ("ident", "qident")
            ):
                column_refs.append(sig[index + 2])
                index += 3
                continue
        index += 1

    # bare column references in the WHEN clause; these resolve against
    # the trigger's own table.  Identifiers inside subqueries are left
    # alone, as they may belong to some other table.
    if when_region is not None:
        depth = 0
        subquery_depths: list[int] = []
        index = when_region[0]
        while index < when_region[1]:
            tok = tokens[sig[index]]
            if tok.kind == "punct":
                if tok.text == "(":
                    depth += 1
                elif tok.text == ")":
                    depth -= 1
                    while subquery_depths and depth < subquery_depths[-1]:
                        subquery_depths.pop()
            elif tok.kind == "ident":
                upper = tok.text.upper()
                if upper == "SELECT" and depth > 0:
                    subquery_depths.append(depth)
                elif not subquery_depths and upper not in (
                    _EXPRESSION_KEYWORDS
                ):
                    prev = tokens[sig[index - 1]] if index > 0 else None
                    next_ = (
                        tokens[sig[index + 1]]
                        if index + 1 < len(sig)
                        else None
                    )
                    if not (
                        prev is not None
                        and prev.kind == "punct"
                        and prev.text == "."
                    ) and not (
                        next_ is not None
                        and next_.kind == "punct"
                        and next_.text in ("(", ".")
                    ):
                        column_refs.append(sig[index])
            index += 1

    replacements: dict[int, str] = {}

    if new_table_name is not None:
        replacements[on_table_index] = _render_identifier(
            new_table_name, tokens[on_table_index]
        )
        # unqualified references to the trigger's own table within the
        # body, in statement position (UPDATE t ..., INSERT INTO t ...,
        # DELETE FROM t ..., etc.)
        index = body_start
        while index < end_pos:
            tok = tokens[sig[index]]
            if (
                tok.kind in ("ident", "qident")
                and _ident_value(tok).lower() == table_name.lower()
            ):
                prev = tokens[sig[index - 1]] if index > 0 else None
                if (
                    prev is not None
                    and prev.kind == "ident"
                    and prev.text.upper() in _TABLE_REF_LEADERS
                ):
                    replacements[sig[index]] = _render_identifier(
                        new_table_name, tok
                    )
            index += 1

    renames = (
        {old.lower(): new for old, new in column_renames.items()}
        if column_renames
        else {}
    )
    dropped = {name.lower() for name in dropped_columns}

    for token_index in column_refs:
        col_token = tokens[token_index]
        col_name = _ident_value(col_token)
        lowered = col_name.lower()
        if lowered in dropped:
            raise TriggerRewriteError(
                f"Trigger '{trigger_name}' on table '{table_name}' "
                f"references column '{col_name}', which is being "
                "dropped by this batch migration, so the trigger "
                "cannot be preserved.  Drop the trigger before the "
                "batch operation and recreate it manually afterwards, "
                "or don't use preserve_triggers."
            )
        if lowered in renames:
            replacements[token_index] = _render_identifier(
                renames[lowered], col_token
            )

    return "".join(
        replacements.get(index, tok.text) for index, tok in enumerate(tokens)
    )
