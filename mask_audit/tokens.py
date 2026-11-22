"""Leaf-token view used by the mask consistency checker.

sqlparse groups tokens into nested structures; the checker works on a flat
stream of leaf tokens with explicit character offsets. Mask placeholders such
as ``<DB>`` are split into several punctuation/name leaves by the lexer, so
they are merged back into a single :class:`LeafToken` here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import sqlparse
from sqlparse import tokens as T

#: Default mask placeholder syntax, e.g. ``<DB>`` or ``<SCHEMA_A>``.
DEFAULT_PLACEHOLDER_RE = re.compile(r'^<[A-Za-z][A-Za-z0-9_]*>$')


@dataclass
class LeafToken:
    """One compared unit: a real leaf token or a merged placeholder."""

    value: str
    ttype: object
    start: int
    end: int
    is_placeholder: bool = False

    @property
    def is_whitespace(self) -> bool:
        return self.ttype in T.Whitespace

    @property
    def is_comment(self) -> bool:
        return self.ttype in T.Comment

    @property
    def is_keyword(self) -> bool:
        return self.ttype in T.Keyword


def leaf_tokens(sql: str) -> list[LeafToken]:
    """Return all leaf tokens of *sql* with absolute character offsets.

    Consecutive leaves that together form a mask placeholder (default shape
    ``<NAME>``) are merged into one token flagged ``is_placeholder``.
    """
    leaves: list[LeafToken] = []
    offset = 0
    for statement in sqlparse.parse(sql):
        for token in statement.flatten():
            value = token.value
            leaves.append(
                LeafToken(
                    value=value,
                    ttype=token.ttype,
                    start=offset,
                    end=offset + len(value),
                ),
            )
            offset += len(value)
    return _merge_placeholders(leaves)


def _merge_placeholders(
    leaves: list[LeafToken],
    pattern: re.Pattern[str] = DEFAULT_PLACEHOLDER_RE,
) -> list[LeafToken]:
    merged: list[LeafToken] = []
    index = 0
    total = len(leaves)
    while index < total:
        current = leaves[index]
        if current.value == '<':
            lookahead = index + 1
            text = '<'
            while lookahead < total and '>' not in text:
                text += leaves[lookahead].value
                lookahead += 1
            if pattern.match(text):
                merged.append(
                    LeafToken(
                        value=text,
                        ttype=T.Name,
                        start=current.start,
                        end=leaves[lookahead - 1].end,
                        is_placeholder=True,
                    ),
                )
                index = lookahead
                continue
        merged.append(current)
        index += 1
    return merged


def significant_tokens(sql: str) -> list[LeafToken]:
    """Leaf tokens with whitespace removed, keeping comments and punctuation."""
    return [token for token in leaf_tokens(sql) if not token.is_whitespace]


