import re
from dataclasses import FrozenInstanceError

import pytest

import sqlparse
from sqlparse.exceptions import SQLParseError


KEY = b"fictional-blind-review-key"

MIGRATION_BEFORE = """-- fictional migration: harbor sparrow
ALTER TABLE glimmer_archive
    ADD COLUMN review_stage VARCHAR(16) DEFAULT 'ember';

UPDATE glimmer_archive
SET review_stage = 'lumen',
    operator_note = 'lumen',
    updated_by = 'orion'
WHERE tenant_code = 'lumen'
  AND operator_note = 'lumen'
  AND access_token = 'kestrel-0001';
"""

MIGRATION_AFTER = MIGRATION_BEFORE.replace(
    "SET review_stage = 'lumen'", "SET review_stage = 'sable'"
)


def test_blind_review_removes_values_and_comments():
    review = sqlparse.blind_review(MIGRATION_BEFORE, key=KEY)
    ticket = review.to_ticket()

    assert KEY.decode() not in ticket
    for secret in ("ember", "lumen", "orion", "kestrel-0001", "harbor sparrow"):
        assert secret not in review.sql
        assert secret not in ticket
        assert secret not in repr(review)
        assert secret not in str(review)

    assert "-- fictional" not in review.sql
    assert "ALTER TABLE glimmer_archive" in review.sql
    assert "UPDATE glimmer_archive" in review.sql
    assert "WHERE tenant_code" in review.sql
    assert "VARCHAR(<number:type_argument:" in review.sql
    assert "<string:default:" in review.sql
    assert str(review) == ticket


def test_markers_distinguish_use_but_preserve_same_use_relations():
    review = sqlparse.blind_review(MIGRATION_BEFORE, key=KEY)

    predicates = {
        item.marker for item in review.occurrences if item.role == "predicate"
    }
    assignments = {
        item.marker for item in review.occurrences if item.role == "assignment"
    }

    assert len(predicates) == 1
    assert predicates.isdisjoint(assignments)


def test_sensitive_predicate_is_internal_only():
    review = sqlparse.blind_review(MIGRATION_BEFORE, key=KEY)

    assert len(review.internal_only) == 1
    assert review.internal_only[0].column == "access_token"
    assert "access_token =" not in review.sql
    assert "INTERNAL REVIEW REQUIRED: column access_token" in review.sql
    assert "kestrel-0001" not in review.sql


def test_marker_stability_is_keyed():
    first = sqlparse.blind_review(MIGRATION_BEFORE, key=KEY)
    repeated = sqlparse.blind_review(MIGRATION_BEFORE, key=KEY)
    other_key = sqlparse.blind_review(MIGRATION_BEFORE, key=b"another-key")

    assert first.sql == repeated.sql
    assert first.sql != other_key.sql


def test_value_only_change_keeps_impact_scope():
    before = sqlparse.blind_review(MIGRATION_BEFORE, key=KEY)
    after = sqlparse.blind_review(MIGRATION_AFTER, key=KEY)
    diff = before.diff(after)

    assert before.scope.key == after.scope.key
    assert not diff.scope_changed
    assert diff.bindings_changed
    assert "Impact scope changed: no" in diff.summary()
    assert "lumen" not in diff.summary()
    assert "sable" not in diff.summary()


def test_local_structure_change_is_visible_in_scope_diff():
    changed = MIGRATION_AFTER.replace(
        "AND operator_note = 'lumen'", "AND region_code = 'lumen'"
    )
    before = sqlparse.blind_review(MIGRATION_AFTER, key=KEY)
    after = sqlparse.blind_review(changed, key=KEY)
    diff = before.diff(after)

    assert diff.scope_changed
    assert diff.changed
    assert "region_code" in "\n".join(diff.scope_changes)
    assert "Impact scope changed: yes" in diff.summary()


def test_review_is_immutable_and_has_no_reverse_mapping():
    review = sqlparse.blind_review(MIGRATION_BEFORE, key=KEY)

    with pytest.raises(FrozenInstanceError):
        review.sql = "changed"
    with pytest.raises(FrozenInstanceError):
        review.occurrences[0].marker = "changed"
    assert not hasattr(review, "values")
    assert set(review.__dataclass_fields__) == {
        "sql",
        "occurrences",
        "internal_only",
        "scope",
    }


def test_markers_are_well_formed():
    review = sqlparse.blind_review(MIGRATION_BEFORE, key=KEY)
    markers = re.findall(r"<[a-z]+:[a-z_]+:[0-9a-f]{10}>", review.sql)

    assert markers
    assert all(marker in review.sql for marker in markers)


def test_list_and_range_predicates_stay_balanced():
    q = chr(39)
    sql_text = (
        "SELECT * FROM demo WHERE access_token IN (" + q + "red" + q
        + ", " + q + "blue" + q + ") AND tenant_code = " + q + "north" + q + ";"
    )
    review = sqlparse.blind_review(sql_text, key=KEY)

    assert "access_token IN" not in review.sql
    assert review.sql.count("(") == review.sql.count(")")
    assert "INTERNAL REVIEW REQUIRED: column access_token" in review.sql
    assert "<string:predicate:" in review.sql


def test_dollar_quoted_literals_are_redacted():
    review = sqlparse.blind_review(
        "SELECT $tag$internal value$tag$ FROM demo_table;", key=KEY
    )

    assert "internal value" not in review.sql
    assert "$tag$" not in review.sql
    assert "<string:projection:" in review.sql


def test_table_scope_does_not_read_literal_text():
    review = sqlparse.blind_review(
        "SELECT " + chr(39) + "FROM secret_table" + chr(39)
        + " FROM public.visible_table;", key=KEY
    )

    assert review.scope.tables == ("public.visible_table",)
    assert "secret_table" not in review.sql
    assert "secret_table" not in str(review.scope)


def test_extra_internal_policy_accepts_qualified_columns():
    review = sqlparse.blind_review(
        "SELECT * FROM public.demo WHERE public.demo.owner_ref = " + chr(39) + "x" + chr(39) + ";",
        key=KEY,
        internal_only_columns=("public.demo.owner_ref",),
    )

    assert review.internal_only[0].column == "owner_ref"
    assert "owner_ref =" not in review.sql


def test_trailing_comments_are_redacted_without_losing_newlines():
    sql_text = (
        "SELECT " + chr(39) + "visible" + chr(39) + " -- private note\n"
        "FROM demo_table; -- trailing note"
    )
    review = sqlparse.blind_review(sql_text, key=KEY)

    assert "private note" not in review.sql
    assert "trailing note" not in review.sql
    assert review.sql.count(chr(10)) == sql_text.count(chr(10))


def test_quoted_identifiers_are_structure_not_literals():
    q = chr(34)
    sql_text = (
        "SELECT " + q + "customer name" + q + " FROM " + q + "orders" + q
        + " WHERE " + q + "tenant code" + q + " = " + chr(39) + "north" + chr(39) + ";"
    )
    review = sqlparse.blind_review(sql_text, key=KEY)

    assert q + "customer name" + q in review.sql
    assert q + "orders" + q in review.sql
    assert q + "tenant code" + q in review.sql
    assert "north" not in review.sql
    assert review.scope.tables == ("orders",)


def test_unparsed_input_fails_closed():
    for sql_text in (
        "SELECT " + chr(39) + "unterminated",
        "SELECT /* unterminated comment",
    ):
        with pytest.raises(SQLParseError):
            sqlparse.blind_review(sql_text, key=KEY)



def test_range_predicate_is_internal_and_balanced():
    sql_text = (
        "SELECT * FROM demo WHERE secret BETWEEN " + chr(39) + "a" + chr(39)
        + " AND " + chr(39) + "b" + chr(39)
        + " AND tenant_code = " + chr(39) + "north" + chr(39) + ";"
    )
    review = sqlparse.blind_review(sql_text, key=KEY)

    assert "secret BETWEEN" not in review.sql
    assert review.sql.count("(") == review.sql.count(")")
    assert "INTERNAL REVIEW REQUIRED: column secret" in review.sql
    assert "<string:predicate:" in review.sql
