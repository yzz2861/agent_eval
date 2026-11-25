"""Local acceptance tests for ordered release-review sign-off.

The scenarios are database-free.  They model a review sheet whose entries
must be signed in the order in which their real DDL statements occur.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace

import pytest

import sqlparse
from sqlparse import tokens as T


@dataclass(frozen=True)
class SignedStatement:
    ticket: str
    identity: str
    ddl: str


@dataclass(frozen=True)
class ReviewCase:
    case_name: str
    script: str
    signed_statements: tuple[SignedStatement, ...]


@dataclass(frozen=True)
class TokenRange:
    start: int
    end: int
    statement_index: int
    ticket: str


CREATE_TABLE_DDL = """CREATE TABLE release_reviews (
    id INTEGER PRIMARY KEY,
    ticket VARCHAR(32) NOT NULL,
    signed_at TIMESTAMP
)"""

ALTER_TABLE_DDL = (
    "ALTER TABLE release_reviews ADD COLUMN reviewer VARCHAR(64)"
)

CREATE_INDEX_DDL = (
    "CREATE INDEX idx_release_reviews_ticket "
    "ON release_reviews (ticket)"
)

QUOTED_CREATE_TABLE_DDL = """CREATE TABLE release_reviews (
    id INTEGER PRIMARY KEY,
    ticket VARCHAR(32) NOT NULL,
    state VARCHAR(200) DEFAULT 'pending; awaiting signature',
    "semicolon; label" VARCHAR(40),
    signed_at TIMESTAMP
)"""

QUOTED_ALTER_TABLE_DDL = """ALTER TABLE release_reviews
    ADD COLUMN decision_note VARCHAR(200)
    DEFAULT 'approved; recorded'"""


CREATE_SIG = SignedStatement(
    "RSO-2026-001",
    "CREATE TABLE release_reviews",
    CREATE_TABLE_DDL,
)
ALTER_SIG = SignedStatement(
    "RSO-2026-002",
    "ALTER TABLE release_reviews",
    ALTER_TABLE_DDL,
)
INDEX_SIG = SignedStatement(
    "RSO-2026-003",
    "CREATE INDEX idx_release_reviews_ticket",
    CREATE_INDEX_DDL,
)
QUOTED_CREATE_SIG = replace(CREATE_SIG, ddl=QUOTED_CREATE_TABLE_DDL)
QUOTED_ALTER_SIG = replace(ALTER_SIG, ddl=QUOTED_ALTER_TABLE_DDL)


COMMENTED_DDL_SCRIPT = f"""-- RSO prose 1; this semicolon is not a statement
{CREATE_TABLE_DDL}; -- trailing note; this semicolon is prose too

-- Another note; no review entry is signed here
{ALTER_TABLE_DDL};

{CREATE_INDEX_DDL}; -- final note; still not a separator
"""

QUOTED_SEMICOLON_SCRIPT = f"""{QUOTED_CREATE_TABLE_DDL};

{QUOTED_ALTER_TABLE_DDL};

{CREATE_INDEX_DDL};
"""

BLANK_LINES_SCRIPT = """

CREATE TABLE release_reviews (
    id INTEGER PRIMARY KEY,

    ticket VARCHAR(32) NOT NULL,
    signed_at TIMESTAMP
);



ALTER TABLE release_reviews ADD COLUMN reviewer VARCHAR(64);


CREATE INDEX idx_release_reviews_ticket ON release_reviews (ticket);


"""


REVIEW_CASES = (
    ReviewCase(
        "line_comment_semicolon",
        COMMENTED_DDL_SCRIPT,
        (CREATE_SIG, ALTER_SIG, INDEX_SIG),
    ),
    ReviewCase(
        "quoted_semicolons",
        QUOTED_SEMICOLON_SCRIPT,
        (QUOTED_CREATE_SIG, QUOTED_ALTER_SIG, INDEX_SIG),
    ),
    ReviewCase(
        "blank_lines",
        BLANK_LINES_SCRIPT,
        (CREATE_SIG, ALTER_SIG, INDEX_SIG),
    ),
)

TICKET_BY_IDENTITY = {
    signed.identity: signed.ticket
    for case in REVIEW_CASES
    for signed in case.signed_statements
}

MOVED_STATEMENT_SCRIPT = "\n\n".join(
    (
        f"{CREATE_TABLE_DDL};",
        f"{CREATE_INDEX_DDL};",
        f"{ALTER_TABLE_DDL};",
    )
) + "\n"
MOVED_SIGN_OFFS = (CREATE_SIG, INDEX_SIG, ALTER_SIG)


_IDENTITY_RE = re.compile(
    r"^(CREATE\s+TABLE|ALTER\s+TABLE|"
    r"CREATE\s+(?:UNIQUE\s+)?INDEX|DROP\s+TABLE)\s+"
    r"(?:IF\s+(?:NOT\s+)?EXISTS\s+)?"
    r"([\w.\"\[\]]+)",
    flags=re.IGNORECASE,
)


def canonical_ddl(value):
    """Return whitespace/comment/semicolon-independent DDL tokens."""
    if isinstance(value, str):
        parsed = sqlparse.parse(value)
        assert len(parsed) == 1
        tokens = parsed[0].flatten()
    else:
        tokens = value.flatten()

    parts = []
    for token in tokens:
        if token.is_whitespace or token.ttype in T.Comment:
            continue
        if token.ttype is T.Punctuation and token.value == ";":
            continue
        parts.append(token.value)
    return " ".join(parts)


def statement_identity(statement):
    canonical = canonical_ddl(statement)
    match = _IDENTITY_RE.match(canonical)
    if match is None:
        raise AssertionError(f"Unrecognized DDL statement: {canonical[:160]}")

    verb = re.sub(r"\s+", " ", match.group(1).upper())
    object_name = match.group(2).strip('"[]').lower()
    return f"{verb} {object_name}"


def _statement_owner(bounds, offset):
    for index, (start, end) in enumerate(bounds):
        if start <= offset < end:
            return index
    raise AssertionError(f"offset {offset} is outside statement ranges {bounds}")


def assert_token_ranges_recover_script(script, statements, tickets):
    """Map every leaf token back to its one original Statement interval."""
    assert len(tickets) == len(statements)

    rendered = [str(statement) for statement in statements]
    rendered_script = "".join(rendered)

    assert script.startswith(rendered_script)
    omitted_tail = script[len(rendered_script):]
    assert not omitted_tail or omitted_tail.isspace(), (
        "parser may omit only a trailing whitespace-only statement"
    )

    bounds = []
    cursor = 0
    for statement_text in rendered:
        bounds.append((cursor, cursor + len(statement_text)))
        cursor += len(statement_text)
    assert cursor == len(rendered_script)

    ranges = []
    for index, statement in enumerate(statements):
        start, end = bounds[index]
        assert script[start:end] == str(statement)
        offset = 0

        for token in statement.flatten():
            length = len(token.value)
            assert length > 0

            token_start = start + offset
            token_end = token_start + length
            assert script[token_start:token_end] == token.value

            assert _statement_owner(bounds, token_start) == index
            assert _statement_owner(bounds, token_end - 1) == index

            ranges.append(
                TokenRange(token_start, token_end, index, tickets[index])
            )
            offset += length

        assert offset == end - start

    return ranges


def assert_script_matches_signoffs(script, expected):
    statements = sqlparse.parse(script)
    split_statements = sqlparse.split(script)

    assert len(statements) == len(expected)
    assert len(split_statements) == len(expected)

    tickets = [signed.ticket for signed in expected]
    ranges = assert_token_ranges_recover_script(script, statements, tickets)

    for index, signed in enumerate(expected):
        statement = statements[index]

        assert split_statements[index] == str(statement).strip()
        assert statement_identity(statement) == signed.identity
        assert canonical_ddl(statement) == canonical_ddl(signed.ddl)
        assert canonical_ddl(split_statements[index]) == canonical_ddl(
            signed.ddl
        )

        ticket_ranges = [
            token_range
            for token_range in ranges
            if token_range.ticket == signed.ticket
        ]
        assert ticket_ranges
        assert {
            token_range.statement_index for token_range in ticket_ranges
        } == {index}

    return statements, split_statements, ranges


def signoff_tickets(script):
    return [
        TICKET_BY_IDENTITY[statement_identity(statement)]
        for statement in sqlparse.parse(script)
    ]


@pytest.mark.parametrize(
    "case",
    REVIEW_CASES,
    ids=[case.case_name for case in REVIEW_CASES],
)
def test_split_api_matches_independent_signoff_list(case):
    assert_script_matches_signoffs(case.script, case.signed_statements)


def test_fixtures_really_contain_protected_semicolons():
    comment_case = next(
        case for case in REVIEW_CASES if case.case_name == "line_comment_semicolon"
    )
    comment_semicolons = 0
    for statement in sqlparse.parse(comment_case.script):
        for token in statement.flatten():
            if token.ttype in T.Comment:
                comment_semicolons += token.value.count(";")
    assert comment_semicolons >= 4

    quoted_case = next(
        case for case in REVIEW_CASES if case.case_name == "quoted_semicolons"
    )
    quoted_semicolons = 0
    for statement in sqlparse.parse(quoted_case.script):
        for token in statement.flatten():
            if token.value[:1] in {"'", '"'}:
                quoted_semicolons += token.value.count(";")
    assert quoted_semicolons >= 3


def test_removing_unrelated_comments_keeps_signoff_identity():
    case = next(
        case for case in REVIEW_CASES if case.case_name == "line_comment_semicolon"
    )
    expected_tickets = [signed.ticket for signed in case.signed_statements]

    assert signoff_tickets(case.script) == expected_tickets

    cleaned_script = sqlparse.format(case.script, strip_comments=True)
    cleaned_statements = sqlparse.parse(cleaned_script)

    assert not any(
        token.ttype in T.Comment
        for statement in cleaned_statements
        for token in statement.flatten()
    )
    assert len(sqlparse.split(cleaned_script)) == len(expected_tickets)
    assert signoff_tickets(cleaned_script) == expected_tickets


def test_moving_real_statement_is_reflected_in_signoff_order():
    statements, split_statements, _ = assert_script_matches_signoffs(
        MOVED_STATEMENT_SCRIPT, MOVED_SIGN_OFFS
    )

    actual_identities = [
        statement_identity(statement) for statement in statements
    ]
    expected_identities = [signed.identity for signed in MOVED_SIGN_OFFS]

    assert actual_identities == expected_identities
    assert actual_identities != [
        signed.identity for signed in REVIEW_CASES[0].signed_statements
    ]
    assert signoff_tickets(MOVED_STATEMENT_SCRIPT) == [
        signed.ticket for signed in MOVED_SIGN_OFFS
    ]
    assert split_statements[1].lstrip().upper().startswith("CREATE INDEX")
    assert split_statements[2].lstrip().upper().startswith("ALTER TABLE")
