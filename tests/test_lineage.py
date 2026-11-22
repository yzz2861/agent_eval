"""Tests for sqlparse.lineage (static pre-review of report definitions)."""

import pytest

from sqlparse import lineage

VIEWS = {
    "orders": ["id", "amount", "customer_id"],
    "invoices": ["id", "total", "issued_at"],
    "customers": ["id", "name"],
}


def review(sql, views=VIEWS):
    return lineage.review(sql, views)


def test_simple_projection_traces_view_column():
    report = review("SELECT id, amount FROM orders")
    assert report.ok
    assert [c.name for c in report] == ["id", "amount"]
    assert report.columns[0].sources == (("orders", "id"),)
    assert report.columns[1].sources == (("orders", "amount"),)


def test_alias_is_used_as_exported_name():
    report = review('SELECT amount AS "摘要" FROM orders')
    assert report.ok
    assert report.columns[0].name == "摘要"
    assert report.columns[0].sources == (("orders", "amount"),)


def test_same_name_columns_go_to_different_queues():
    report = review(
        'SELECT o.amount AS "摘要", i.total AS "摘要" '
        "FROM orders o, invoices i"
    )
    assert report.ok
    first, second = report.columns
    assert first.name == second.name == "摘要"
    assert first.queue != second.queue
    queues = report.queues()
    assert queues["orders.amount"] == ["摘要"]
    assert queues["invoices.total"] == ["摘要"]


def test_qualified_and_aliased_sources():
    report = review(
        "SELECT o.id, c.name AS customer "
        "FROM orders o JOIN customers c ON o.customer_id = c.id"
    )
    assert report.ok
    assert report.columns[0].sources == (("orders", "id"),)
    assert report.columns[1].sources == (("customers", "name"),)


def test_subquery_sources_are_traced():
    report = review(
        "SELECT t.x, t.y FROM (SELECT amount AS x, id AS y FROM orders) t"
    )
    assert report.ok
    assert report.columns[0].sources == (("orders", "amount"),)
    assert report.columns[1].sources == (("orders", "id"),)


def test_nested_subquery_sources_are_traced():
    report = review(
        "SELECT o.z FROM "
        "(SELECT t.total AS z FROM (SELECT total FROM invoices) t) o"
    )
    assert report.ok
    assert report.columns[0].sources == (("invoices", "total"),)


def test_function_arguments_are_traced():
    report = review("SELECT upper(name) AS label FROM customers")
    assert report.ok
    assert report.columns[0].name == "label"
    assert report.columns[0].sources == (("customers", "name"),)


def test_wildcard_expands_to_manifest_columns():
    report = review("SELECT * FROM customers")
    assert report.ok
    assert [c.name for c in report] == ["id", "name"]
    assert report.columns[1].sources == (("customers", "name"),)


def test_qualified_wildcard_expands_single_source():
    report = review("SELECT c.* FROM customers c, orders o")
    assert report.ok
    assert [c.name for c in report] == ["id", "name"]
    assert all(c.sources[0][0] == "customers" for c in report)


def test_literal_column_has_no_source():
    report = review("SELECT 1 AS one, id FROM orders")
    assert report.ok
    constant, ident = report.columns
    assert constant.sources == ()
    assert constant.queue == "constant"
    assert ident.sources == (("orders", "id"),)


def test_partial_evidence_keeps_known_sources_and_gaps():
    report = review(
        "SELECT amount, missing_col, upper(name) AS u FROM orders"
    )
    assert not report.ok
    known, unresolved, broken = report.columns
    assert known.complete
    assert unresolved.sources == ()
    assert unresolved.gaps == (
        "column 'missing_col' is not declared in view 'orders'",
    )
    assert unresolved.queue == "unresolved"
    # the function argument is not a column of the FROM view
    assert broken.sources == ()
    assert broken.gaps == ("column 'name' is not declared in view 'orders'",)


def test_ambiguous_column_records_candidates_and_gap():
    report = review("SELECT id FROM orders, invoices")
    assert not report.ok
    (column,) = report.columns
    assert column.sources == (("invoices", "id"), ("orders", "id"))
    assert len(column.gaps) == 1
    assert "ambiguous" in column.gaps[0]


def test_expression_combines_sources():
    report = review(
        "SELECT o.amount + i.total AS merged FROM orders o, invoices i"
    )
    assert report.ok
    assert report.columns[0].sources == (
        ("invoices", "total"),
        ("orders", "amount"),
    )
    assert report.columns[0].queue == "invoices.total+orders.amount"


def test_removed_view_declaration_stops_review():
    sql = "SELECT o.id, c.name FROM orders o, customers c"
    reduced = {k: v for k, v in VIEWS.items() if k != "customers"}
    with pytest.raises(lineage.UnknownViewError, match="customers"):
        lineage.review(sql, reduced)


def test_view_inside_subquery_must_be_declared():
    with pytest.raises(lineage.UnknownViewError, match="secret"):
        review("SELECT t.x FROM (SELECT x FROM secret) t")


def test_non_select_statement_is_rejected():
    with pytest.raises(lineage.UnsupportedStatementError):
        review("DELETE FROM orders")


def test_insert_is_rejected():
    with pytest.raises(lineage.UnsupportedStatementError):
        review("INSERT INTO orders (id) VALUES (1)")


def test_union_is_rejected():
    with pytest.raises(lineage.UnsupportedStatementError):
        review("SELECT id FROM orders UNION SELECT id FROM invoices")


def test_cte_is_rejected():
    with pytest.raises(lineage.UnsupportedStatementError):
        review("WITH x AS (SELECT id FROM orders) SELECT * FROM x")


def test_derived_table_requires_alias():
    with pytest.raises(lineage.UnsupportedStatementError):
        review("SELECT x FROM (SELECT id AS x FROM orders)")


def test_multiple_statements_are_reviewed():
    report = review("SELECT id FROM orders; SELECT total FROM invoices;")
    assert report.ok
    assert [c.name for c in report] == ["id", "total"]


def test_distinct_and_group_by_are_allowed():
    report = review(
        "SELECT DISTINCT customer_id FROM orders GROUP BY customer_id"
    )
    assert report.ok
    assert report.columns[0].sources == (("orders", "customer_id"),)


def test_views_argument_must_be_a_mapping():
    with pytest.raises(TypeError):
        lineage.review("SELECT id FROM orders", ["orders"])
    with pytest.raises(TypeError):
        lineage.review("SELECT id FROM orders", {"orders": "id"})
