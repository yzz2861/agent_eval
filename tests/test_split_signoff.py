# Local acceptance tests for statement sign-off in review order.
#
# A review sheet is signed off statement by statement, in order. These
# tests pin down that semicolons inside line comments or quoted strings
# never become extra statements, that blank lines are irrelevant, and
# that the split API agrees with an independently declared sign-off
# list. Everything is self-contained; no database is ever contacted.

import sqlparse

# Independently declared sign-off list: the canonical statements a
# reviewer signs off, in order. This list is the source of truth and
# is deliberately written separately from the SQL scripts below.
SIGNOFF_LIST = [
    "CREATE TABLE review_item (id INTEGER PRIMARY KEY, title TEXT)",
    "ALTER TABLE review_item ADD COLUMN note TEXT",
    "INSERT INTO review_item (id, title) VALUES (1, 'draft; pending')",
]

# Irrelevant comments: they may carry semicolons, but those semicolons
# must never be accepted as statement separators.
LEADING_COMMENT = "-- review sheet: 2026-11-26; owner: qa; do not split\n"
TRAILING_COMMENT = " -- checked; ok"

DDL_SCRIPT = (
    LEADING_COMMENT
    + "CREATE TABLE review_item (id INTEGER PRIMARY KEY, title TEXT);\n"
    + "\n"
    + "ALTER TABLE review_item ADD COLUMN note TEXT;" + TRAILING_COMMENT + "\n"
    + "\n"
    + "\n"
    + "INSERT INTO review_item (id, title) VALUES (1, 'draft; pending');\n"
)


def _canonical(text):
    """Reduce a statement to its sign-off identity.

    Line comments, blank lines, surrounding whitespace and the
    terminating semicolon are not part of the identity.
    """
    lines = []
    for line in text.splitlines():
        line = line.split("--", 1)[0].strip()
        if line:
            lines.append(line)
    return " ".join(lines).rstrip(";").strip()


def _signoff(sql):
    """Sign off a script: canonical statements via the split API."""
    return [_canonical(chunk) for chunk in sqlparse.split(sql)]


def test_split_matches_signoff_list_in_order():
    signed = _signoff(DDL_SCRIPT)
    assert len(signed) == len(SIGNOFF_LIST)
    for position, (accepted, expected) in enumerate(zip(signed, SIGNOFF_LIST)):
        assert accepted == expected, "mismatch at sign-off row %d" % position


def test_comment_semicolons_never_create_statements():
    sql = (
        "-- ;;;\n"
        "CREATE TABLE t (id INT); -- done;\n"
        "-- another; comment; with; semicolons\n"
    )
    assert _signoff(sql) == ["CREATE TABLE t (id INT)"]


def test_quoted_semicolons_never_create_statements():
    sql = "INSERT INTO t VALUES ('a;b', \"c;d\");\n"
    assert _signoff(sql) == ["INSERT INTO t VALUES ('a;b', \"c;d\")"]


def test_blank_lines_do_not_change_signoff():
    variants = [
        "CREATE TABLE a (id INT);\nCREATE TABLE b (id INT);\n",
        "CREATE TABLE a (id INT);\n\nCREATE TABLE b (id INT);\n",
        "\n\nCREATE TABLE a (id INT);\n\n\n\nCREATE TABLE b (id INT);\n\n",
    ]
    expected = ["CREATE TABLE a (id INT)", "CREATE TABLE b (id INT)"]
    for sql in variants:
        assert _signoff(sql) == expected


def test_token_ranges_relocate_to_same_original_statement():
    # Parsed statements partition the original script: each statement's
    # token range maps back to exactly one contiguous slice of the
    # original text, in order, with no gaps or overlaps.
    offset = 0
    statements = sqlparse.parse(DDL_SCRIPT)
    assert len(statements) == len(SIGNOFF_LIST)
    for stmt in statements:
        text = str(stmt)
        assert DDL_SCRIPT[offset:offset + len(text)] == text
        offset += len(text)
    # Only insignificant whitespace may fall outside the token ranges.
    assert DDL_SCRIPT[offset:].strip() == ""

    # The split API must point back into the same original statement
    # too: every chunk is found in the script at a monotonically
    # increasing position.
    cursor = 0
    for chunk in sqlparse.split(DDL_SCRIPT):
        found = DDL_SCRIPT.index(chunk, cursor)
        assert found >= cursor
        cursor = found + len(chunk)


def test_removing_irrelevant_comments_preserves_signoff():
    with_comments = _signoff(DDL_SCRIPT)
    without_comments = _signoff(sqlparse.format(
        DDL_SCRIPT, strip_comments=True))
    assert without_comments == with_comments == SIGNOFF_LIST


def test_moving_real_statements_is_reflected_in_order():
    moved = (
        "ALTER TABLE review_item ADD COLUMN note TEXT;\n"
        "CREATE TABLE review_item (id INTEGER PRIMARY KEY, title TEXT);\n"
        "INSERT INTO review_item (id, title) VALUES (1, 'draft; pending');\n"
    )
    signed = _signoff(moved)
    assert signed == [SIGNOFF_LIST[1], SIGNOFF_LIST[0], SIGNOFF_LIST[2]]
    assert signed != SIGNOFF_LIST
