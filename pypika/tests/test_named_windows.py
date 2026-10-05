import sqlite3
import unittest

from pypika import Order, Query, QueryException, Table, Window
from pypika import analytics as an
from pypika.dialects import MSSQLQuery, OracleQuery, PostgreSQLQuery, SQLLiteQuery


class NamedWindowSQLTests(unittest.TestCase):
    table_abc = Table("abc")

    def test_shared_window_referenced_by_multiple_functions(self):
        q = (
            PostgreSQLQuery.from_(self.table_abc)
            .select(
                an.Rank().over_window("w"),
                an.DenseRank().over_window("w"),
                an.RowNumber().over_window("w"),
                an.Sum(self.table_abc.foo).over_window("w"),
                an.Avg(self.table_abc.foo).over_window("w"),
                an.Count(self.table_abc.foo).over_window("w"),
            )
            .window("w", Window().partition_by(self.table_abc.foo).orderby(self.table_abc.date))
        )

        self.assertEqual(
            'SELECT RANK() OVER "w",DENSE_RANK() OVER "w",ROW_NUMBER() OVER "w",'
            'SUM("foo") OVER "w",AVG("foo") OVER "w",COUNT("foo") OVER "w" '
            'FROM "abc" WINDOW "w" AS (PARTITION BY "foo" ORDER BY "date")',
            str(q),
        )

    def test_named_window_sqllite(self):
        q = (
            SQLLiteQuery.from_(self.table_abc)
            .select(an.Rank().over_window("w"))
            .window("w", Window().partition_by(self.table_abc.foo).orderby(self.table_abc.date))
        )

        self.assertEqual(
            'SELECT RANK() OVER "w" FROM "abc" WINDOW "w" AS (PARTITION BY "foo" ORDER BY "date")',
            str(q),
        )

    def test_named_window_generic_query(self):
        q = (
            Query.from_(self.table_abc)
            .select(an.Rank().over_window("w"))
            .window("w", Window().partition_by(self.table_abc.foo))
        )

        self.assertEqual('SELECT RANK() OVER "w" FROM "abc" WINDOW "w" AS (PARTITION BY "foo")', str(q))

    def test_window_definition_with_frame(self):
        q = (
            PostgreSQLQuery.from_(self.table_abc)
            .select(an.Sum(self.table_abc.foo).over_window("w"))
            .window(
                "w",
                Window()
                .partition_by(self.table_abc.foo)
                .orderby(self.table_abc.date)
                .rows(an.Preceding(), an.CURRENT_ROW),
            )
        )

        self.assertEqual(
            'SELECT SUM("foo") OVER "w" FROM "abc" '
            'WINDOW "w" AS (PARTITION BY "foo" ORDER BY "date" ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)',
            str(q),
        )

    def test_window_definition_orderby_with_orientation(self):
        q = (
            PostgreSQLQuery.from_(self.table_abc)
            .select(an.Rank().over_window("w"))
            .window("w", Window().orderby(self.table_abc.date, order=Order.desc))
        )

        self.assertEqual(
            'SELECT RANK() OVER "w" FROM "abc" WINDOW "w" AS (ORDER BY "date" DESC)',
            str(q),
        )

    def test_reference_extended_with_orderby(self):
        q = (
            PostgreSQLQuery.from_(self.table_abc)
            .select(an.RowNumber().over_window("w").orderby(self.table_abc.date))
            .window("w", Window().partition_by(self.table_abc.foo))
        )

        self.assertEqual(
            'SELECT ROW_NUMBER() OVER("w" ORDER BY "date") FROM "abc" WINDOW "w" AS (PARTITION BY "foo")',
            str(q),
        )

    def test_reference_extended_with_frame(self):
        q = (
            PostgreSQLQuery.from_(self.table_abc)
            .select(an.Sum(self.table_abc.foo).over_window("w").rows(an.Preceding(1), an.CURRENT_ROW))
            .window("w", Window().partition_by(self.table_abc.foo).orderby(self.table_abc.date))
        )

        self.assertEqual(
            'SELECT SUM("foo") OVER("w" ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM "abc" '
            'WINDOW "w" AS (PARTITION BY "foo" ORDER BY "date")',
            str(q),
        )

    def test_chained_window_definitions(self):
        q = (
            SQLLiteQuery.from_(self.table_abc)
            .select(an.Sum(self.table_abc.foo).over_window("w2").rows(an.Preceding(1)))
            .window("w", Window().partition_by(self.table_abc.foo))
            .window("w2", Window("w").orderby(self.table_abc.date, order=Order.desc))
        )

        self.assertEqual(
            'SELECT SUM("foo") OVER("w2" ROWS 1 PRECEDING) FROM "abc" '
            'WINDOW "w" AS (PARTITION BY "foo"),"w2" AS ("w" ORDER BY "date" DESC)',
            str(q),
        )

    def test_mixed_named_and_anonymous_windows(self):
        q = (
            Query.from_(self.table_abc)
            .select(
                an.Rank().over(self.table_abc.foo).orderby(self.table_abc.date),
                an.Rank().over_window("w"),
            )
            .window("w", Window().partition_by(self.table_abc.foo))
        )

        self.assertEqual(
            'SELECT RANK() OVER(PARTITION BY "foo" ORDER BY "date"),RANK() OVER "w" '
            'FROM "abc" WINDOW "w" AS (PARTITION BY "foo")',
            str(q),
        )

    def test_window_clause_positioned_before_orderby(self):
        q = (
            PostgreSQLQuery.from_(self.table_abc)
            .select(an.Rank().over_window("w"))
            .window("w", Window().partition_by(self.table_abc.foo))
            .orderby(self.table_abc.date)
        )

        self.assertEqual(
            'SELECT RANK() OVER "w" FROM "abc" WINDOW "w" AS (PARTITION BY "foo") ORDER BY "date"',
            str(q),
        )


class NamedWindowValidationTests(unittest.TestCase):
    table_abc = Table("abc")

    def test_unknown_window_reference_raises(self):
        q = (
            SQLLiteQuery.from_(self.table_abc)
            .select(an.Rank().over_window("missing"))
            .window("w", Window().partition_by(self.table_abc.foo))
        )

        with self.assertRaisesRegex(QueryException, 'Window "missing" does not exist'):
            str(q)

    def test_unknown_window_base_raises(self):
        q = (
            SQLLiteQuery.from_(self.table_abc)
            .select(an.Rank().over_window("w"))
            .window("w", Window("missing").orderby(self.table_abc.date))
        )

        with self.assertRaisesRegex(QueryException, 'Window "missing" does not exist'):
            str(q)

    def test_window_reference_cycle_raises(self):
        q = (
            SQLLiteQuery.from_(self.table_abc)
            .select(an.Rank().over_window("w1"))
            .window("w1", Window("w2"))
            .window("w2", Window("w1"))
        )

        with self.assertRaisesRegex(QueryException, "Window reference cycle detected"):
            str(q)

    def test_window_self_reference_cycle_raises(self):
        q = SQLLiteQuery.from_(self.table_abc).select(an.Rank().over_window("w")).window("w", Window("w"))

        with self.assertRaisesRegex(QueryException, "Window reference cycle detected"):
            str(q)

    def test_function_cannot_add_partition_by_to_named_window(self):
        q = (
            SQLLiteQuery.from_(self.table_abc)
            .select(an.Rank().over_window("w").over(self.table_abc.foo))
            .window("w", Window().orderby(self.table_abc.date))
        )

        with self.assertRaisesRegex(QueryException, 'Cannot override PARTITION BY clause of window "w"'):
            str(q)

    def test_window_definition_cannot_add_partition_by_to_base(self):
        q = (
            SQLLiteQuery.from_(self.table_abc)
            .select(an.Rank().over_window("w2"))
            .window("w", Window().orderby(self.table_abc.date))
            .window("w2", Window("w").partition_by(self.table_abc.foo))
        )

        with self.assertRaisesRegex(QueryException, 'Cannot override PARTITION BY clause of window "w"'):
            str(q)

    def test_function_cannot_override_orderby_of_named_window(self):
        q = (
            SQLLiteQuery.from_(self.table_abc)
            .select(an.Rank().over_window("w").orderby(self.table_abc.date))
            .window("w", Window().orderby(self.table_abc.foo))
        )

        with self.assertRaisesRegex(QueryException, 'Cannot override ORDER BY clause of window "w"'):
            str(q)

    def test_window_definition_cannot_override_orderby_of_base(self):
        q = (
            SQLLiteQuery.from_(self.table_abc)
            .select(an.Rank().over_window("w2"))
            .window("w", Window().orderby(self.table_abc.date))
            .window("w2", Window("w").orderby(self.table_abc.foo))
        )

        with self.assertRaisesRegex(QueryException, 'Cannot override ORDER BY clause of window "w"'):
            str(q)

    def test_function_cannot_override_frame_of_named_window(self):
        q = (
            SQLLiteQuery.from_(self.table_abc)
            .select(an.Sum(self.table_abc.foo).over_window("w").rows(an.Preceding(1)))
            .window("w", Window().orderby(self.table_abc.date).rows(an.Preceding(2)))
        )

        with self.assertRaisesRegex(QueryException, 'Cannot override frame clause of window "w"'):
            str(q)

    def test_window_definition_cannot_extend_base_with_frame(self):
        q = (
            SQLLiteQuery.from_(self.table_abc)
            .select(an.Sum(self.table_abc.foo).over_window("w2"))
            .window("w", Window().orderby(self.table_abc.date).rows(an.Preceding(2)))
            .window("w2", Window("w"))
        )

        with self.assertRaisesRegex(QueryException, 'Cannot override frame clause of window "w"'):
            str(q)

    def test_duplicate_window_name_raises(self):
        with self.assertRaisesRegex(QueryException, 'Window "w" is already defined'):
            (
                SQLLiteQuery.from_(self.table_abc)
                .select(an.Rank().over_window("w"))
                .window("w", Window().partition_by(self.table_abc.foo))
                .window("w", Window().partition_by(self.table_abc.bar))
            )

    def test_unsupported_dialects_reject_window_clause(self):
        for query_cls in (MSSQLQuery, OracleQuery):
            with self.subTest(dialect=query_cls.__name__):
                with self.assertRaisesRegex(QueryException, "WINDOW clause is not supported"):
                    (
                        query_cls.from_(self.table_abc)
                        .select(an.Rank().over_window("w"))
                        .window("w", Window().partition_by(self.table_abc.foo))
                    )


class NamedWindowScopeTests(unittest.TestCase):
    table_abc = Table("abc")

    def test_subquery_window_definitions_do_not_leak_into_outer_query(self):
        subquery = (
            SQLLiteQuery.from_(self.table_abc)
            .select(an.Rank().over_window("w").as_("r"))
            .window("w", Window().partition_by(self.table_abc.foo))
            .as_("sq")
        )
        q = (
            SQLLiteQuery.from_(subquery)
            .select(an.Rank().over_window("w"))
            .window("w", Window().partition_by(self.table_abc.bar))
        )

        self.assertEqual(
            'SELECT RANK() OVER "w" FROM ('
            'SELECT RANK() OVER "w" "r" FROM "abc" WINDOW "w" AS (PARTITION BY "foo")'
            ') "sq" WINDOW "w" AS (PARTITION BY "abc"."bar")',
            str(q),
        )

    def test_outer_query_cannot_reference_subquery_window(self):
        subquery = (
            SQLLiteQuery.from_(self.table_abc)
            .select(an.Rank().over_window("inner_w").as_("r"))
            .window("inner_w", Window().partition_by(self.table_abc.foo))
            .as_("sq")
        )
        q = SQLLiteQuery.from_(subquery).select(an.Rank().over_window("inner_w"))

        with self.assertRaisesRegex(QueryException, 'Window "inner_w" does not exist'):
            str(q)


class NamedWindowImmutabilityTests(unittest.TestCase):
    table_abc = Table("abc")

    def test_deriving_window_definition_does_not_modify_original(self):
        base = Window().partition_by(self.table_abc.foo)
        base.orderby(self.table_abc.date)

        self.assertEqual('(PARTITION BY "foo")', base.get_sql(quote_char='"'))

    def test_chained_reuse_does_not_modify_original_query(self):
        q1 = (
            SQLLiteQuery.from_(self.table_abc)
            .select(an.Rank().over_window("w"))
            .window("w", Window().partition_by(self.table_abc.foo))
        )
        q1_sql = str(q1)

        q2 = q1.window("w2", Window("w").orderby(self.table_abc.date)).select(an.RowNumber().over_window("w2"))

        self.assertEqual(q1_sql, str(q1))
        self.assertNotEqual(q1_sql, str(q2))


class NamedWindowExecutionTests(unittest.TestCase):
    table = Table("scores")

    def setUp(self):
        self.connection = sqlite3.connect(":memory:")
        self.connection.execute("CREATE TABLE scores (team TEXT, player TEXT, points INT, played INT)")
        self.connection.executemany(
            "INSERT INTO scores VALUES (?,?,?,?)",
            [
                ("a", "p1", 10, 3),
                ("a", "p2", 20, 1),
                ("a", "p3", 30, 2),
                ("b", "p4", 40, 2),
                ("b", "p5", 50, 1),
            ],
        )

    def tearDown(self):
        self.connection.close()

    def fetchall(self, query):
        return self.connection.execute(str(query)).fetchall()

    def window_functions(self):
        return [
            an.Rank(),
            an.DenseRank(),
            an.RowNumber(),
            an.Sum(self.table.points),
            an.Avg(self.table.points),
            an.Count(self.table.points),
        ]

    def test_named_window_matches_expanded_window(self):
        named = (
            SQLLiteQuery.from_(self.table)
            .select(*[f.over_window("w") for f in self.window_functions()])
            .window("w", Window().partition_by(self.table.team).orderby(self.table.played))
        )
        expanded = SQLLiteQuery.from_(self.table).select(
            *[f.over(self.table.team).orderby(self.table.played) for f in self.window_functions()]
        )

        self.assertEqual(self.fetchall(named), self.fetchall(expanded))

    def test_chained_window_matches_expanded_window(self):
        named = (
            SQLLiteQuery.from_(self.table)
            .select(an.Sum(self.table.points).over_window("w2").rows(an.Preceding(1), an.CURRENT_ROW))
            .window("w", Window().partition_by(self.table.team))
            .window("w2", Window("w").orderby(self.table.played))
        )
        expanded = SQLLiteQuery.from_(self.table).select(
            an.Sum(self.table.points)
            .over(self.table.team)
            .orderby(self.table.played)
            .rows(an.Preceding(1), an.CURRENT_ROW)
        )

        self.assertEqual(self.fetchall(named), self.fetchall(expanded))

    def test_reused_window_definition_is_not_modified_by_chained_query(self):
        q1 = (
            SQLLiteQuery.from_(self.table)
            .select(an.Rank().over_window("w"))
            .window("w", Window().partition_by(self.table.team))
        )
        rows_before = self.fetchall(q1)

        q2 = q1.window("w2", Window("w").orderby(self.table.played)).select(an.RowNumber().over_window("w2"))
        self.fetchall(q2)

        self.assertEqual(rows_before, self.fetchall(q1))
