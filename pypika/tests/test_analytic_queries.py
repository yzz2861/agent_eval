import sqlite3
import unittest

from pypika import Criterion, JoinType, MySQLQuery, Order, Query, QueryException, Table, Tables
from pypika import analytics as an
from pypika.analytics import Lag, Lead
from pypika.dialects import PostgreSQLQuery, SQLLiteQuery

__author__ = "Timothy Heys"
__email__ = "theys@kayak.com"


class RankTests(unittest.TestCase):
    table_abc, table_efg = Tables("abc", "efg")

    def test_rank(self):
        expr = an.Rank().over(self.table_abc.foo).orderby(self.table_abc.date)

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT " "RANK() " 'OVER(PARTITION BY "foo" ORDER BY "date") ' 'FROM "abc"',
            str(q),
        )

    def test_dense_rank(self):
        expr = an.DenseRank().over(self.table_abc.foo).orderby(self.table_abc.date)

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT " "DENSE_RANK() " 'OVER(PARTITION BY "foo" ORDER BY "date") ' 'FROM "abc"',
            str(q),
        )

    def test_row_number(self):
        expr = an.RowNumber().over(self.table_abc.foo).orderby(self.table_abc.date)

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT " "ROW_NUMBER() " 'OVER(PARTITION BY "foo" ORDER BY "date") ' 'FROM "abc"',
            str(q),
        )

    def test_rank_with_alias(self):
        expr = an.Rank().over(self.table_abc.foo).orderby(self.table_abc.date).as_("rank")

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT " "RANK() " 'OVER(PARTITION BY "foo" ORDER BY "date") "rank" ' 'FROM "abc"',
            str(q),
        )

    def test_multiple_partitions(self):
        expr = an.Rank().orderby(self.table_abc.date).over(self.table_abc.foo, self.table_abc.bar)

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT " "RANK() " 'OVER(PARTITION BY "foo","bar" ORDER BY "date") ' 'FROM "abc"',
            str(q),
        )

    def test_ntile_no_partition_or_order_invalid_sql(self):
        expr = an.NTile(5)

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual("SELECT " "NTILE(5) " 'FROM "abc"', str(q))

    def test_ntile_with_partition(self):
        expr = an.NTile(5).over(self.table_abc.foo)

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual("SELECT " "NTILE(5) " 'OVER(PARTITION BY "foo") ' 'FROM "abc"', str(q))

    def test_ntile_with_order(self):
        expr = an.NTile(5).orderby(self.table_abc.date)

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual("SELECT " "NTILE(5) " 'OVER(ORDER BY "date") ' 'FROM "abc"', str(q))

    def test_ntile_with_partition_and_order(self):
        expr = an.NTile(5).over(self.table_abc.foo).orderby(self.table_abc.date)

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT " "NTILE(5) " 'OVER(PARTITION BY "foo" ORDER BY "date") ' 'FROM "abc"',
            str(q),
        )

    def test_first_value(self):
        expr = an.FirstValue(self.table_abc.fizz).over(self.table_abc.foo).orderby(self.table_abc.date)

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT " 'FIRST_VALUE("fizz") ' 'OVER(PARTITION BY "foo" ORDER BY "date") ' 'FROM "abc"',
            str(q),
        )

    def test_first_value_ignore_nulls(self):
        expr = an.FirstValue(self.table_abc.fizz).over(self.table_abc.foo).orderby(self.table_abc.date).ignore_nulls()

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT " 'FIRST_VALUE("fizz" IGNORE NULLS) ' 'OVER(PARTITION BY "foo" ORDER BY "date") ' 'FROM "abc"',
            str(q),
        )

    def test_first_value_ignore_nulls_first(self):
        expr = an.FirstValue(self.table_abc.fizz).ignore_nulls().over(self.table_abc.foo).orderby(self.table_abc.date)

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT " 'FIRST_VALUE("fizz" IGNORE NULLS) ' 'OVER(PARTITION BY "foo" ORDER BY "date") ' 'FROM "abc"',
            str(q),
        )

    def test_first_value_multi_argument(self):
        expr = (
            an.FirstValue(self.table_abc.fizz, self.table_abc.buzz)
            .over(self.table_abc.foo)
            .orderby(self.table_abc.date)
        )

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT " 'FIRST_VALUE("fizz","buzz") ' 'OVER(PARTITION BY "foo" ORDER BY "date") ' 'FROM "abc"',
            str(q),
        )

    def test_last_value(self):
        expr = an.LastValue(self.table_abc.fizz).over(self.table_abc.foo).orderby(self.table_abc.date)

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT " 'LAST_VALUE("fizz") ' 'OVER(PARTITION BY "foo" ORDER BY "date") ' 'FROM "abc"',
            str(q),
        )

    def test_filter(self):
        expr = (
            an.LastValue(self.table_abc.fizz)
            .filter(Criterion.all([self.table_abc.bar == True]))
            .over(self.table_abc.foo)
            .orderby(self.table_abc.date)
        )

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT "
            'LAST_VALUE("fizz") '
            'FILTER(WHERE "bar"=true) '
            'OVER(PARTITION BY "foo" ORDER BY "date") '
            'FROM "abc"',
            str(q),
        )

    def test_filter_quote_table_in_filter(self):
        expr = (
            an.LastValue(self.table_efg.fizz)
            .filter(self.table_efg.filed.eq('yes'))
            .over(self.table_efg.foo)
            .orderby(self.table_efg.date)
        )

        q = (
            Query.from_(self.table_abc)
            .inner_join(self.table_efg)
            .on(self.table_abc.id.eq(self.table_efg.id))
            .select(expr)
        )

        self.assertEqual(
            'SELECT '
            'LAST_VALUE("efg"."fizz") '
            'FILTER(WHERE "efg"."filed"=\'yes\') '
            'OVER(PARTITION BY "efg"."foo" ORDER BY "efg"."date") '
            'FROM "abc" '
            'JOIN "efg" ON "abc"."id"="efg"."id"',
            str(q),
        )

    def test_orderby_asc(self):
        expr = an.LastValue(self.table_abc.fizz).over(self.table_abc.foo).orderby(self.table_abc.date, order=Order.asc)

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT " 'LAST_VALUE("fizz") ' 'OVER(PARTITION BY "foo" ORDER BY "date" ASC) ' 'FROM "abc"',
            str(q),
        )

    def test_orderby_desc(self):
        expr = an.LastValue(self.table_abc.fizz).over(self.table_abc.foo).orderby(self.table_abc.date, order=Order.desc)

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT " 'LAST_VALUE("fizz") ' 'OVER(PARTITION BY "foo" ORDER BY "date" DESC) ' 'FROM "abc"',
            str(q),
        )

    def test_last_value_multi_argument(self):
        expr = (
            an.LastValue(self.table_abc.fizz, self.table_abc.buzz).over(self.table_abc.foo).orderby(self.table_abc.date)
        )

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT " 'LAST_VALUE("fizz","buzz") ' 'OVER(PARTITION BY "foo" ORDER BY "date") ' 'FROM "abc"',
            str(q),
        )

    def test_last_value_ignore_nulls(self):
        expr = an.LastValue(self.table_abc.fizz).over(self.table_abc.foo).orderby(self.table_abc.date).ignore_nulls()

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT " 'LAST_VALUE("fizz" IGNORE NULLS) ' 'OVER(PARTITION BY "foo" ORDER BY "date") ' 'FROM "abc"',
            str(q),
        )

    def test_median(self):
        expr = an.Median(self.table_abc.fizz).over(self.table_abc.foo, self.table_abc.bar).orderby(self.table_abc.date)

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT " 'MEDIAN("fizz") ' 'OVER(PARTITION BY "foo","bar" ORDER BY "date") ' 'FROM "abc"',
            str(q),
        )

    def test_avg(self):
        expr = an.Avg(self.table_abc.fizz).over(self.table_abc.foo, self.table_abc.bar).orderby(self.table_abc.date)

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT " 'AVG("fizz") ' 'OVER(PARTITION BY "foo","bar" ORDER BY "date") ' 'FROM "abc"',
            str(q),
        )

    def test_stddev(self):
        expr = an.StdDev(self.table_abc.fizz).over(self.table_abc.foo, self.table_abc.bar).orderby(self.table_abc.date)

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT " 'STDDEV("fizz") ' 'OVER(PARTITION BY "foo","bar" ORDER BY "date") ' 'FROM "abc"',
            str(q),
        )

    def test_stddev_pop(self):
        expr = (
            an.StdDevPop(self.table_abc.fizz).over(self.table_abc.foo, self.table_abc.bar).orderby(self.table_abc.date)
        )

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT " 'STDDEV_POP("fizz") ' 'OVER(PARTITION BY "foo","bar" ORDER BY "date") ' 'FROM "abc"',
            str(q),
        )

    def test_stddev_samp(self):
        expr = (
            an.StdDevSamp(self.table_abc.fizz).over(self.table_abc.foo, self.table_abc.bar).orderby(self.table_abc.date)
        )

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT " 'STDDEV_SAMP("fizz") ' 'OVER(PARTITION BY "foo","bar" ORDER BY "date") ' 'FROM "abc"',
            str(q),
        )

    def test_variance(self):
        expr = (
            an.Variance(self.table_abc.fizz).over(self.table_abc.foo, self.table_abc.bar).orderby(self.table_abc.date)
        )

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT " 'VARIANCE("fizz") ' 'OVER(PARTITION BY "foo","bar" ORDER BY "date") ' 'FROM "abc"',
            str(q),
        )

    def test_var_pop(self):
        expr = an.VarPop(self.table_abc.fizz).over(self.table_abc.foo, self.table_abc.bar).orderby(self.table_abc.date)

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT " 'VAR_POP("fizz") ' 'OVER(PARTITION BY "foo","bar" ORDER BY "date") ' 'FROM "abc"',
            str(q),
        )

    def test_var_samp(self):
        expr = an.VarSamp(self.table_abc.fizz).over(self.table_abc.foo, self.table_abc.bar).orderby(self.table_abc.date)

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT " 'VAR_SAMP("fizz") ' 'OVER(PARTITION BY "foo","bar" ORDER BY "date") ' 'FROM "abc"',
            str(q),
        )

    def test_table_prefixes_used_in_analytic_functions(self):
        expr = an.Rank().over(self.table_abc.foo).orderby(self.table_efg.date)

        query = (
            Query.from_(self.table_abc)
            .join(self.table_efg, how=JoinType.left)
            .on(self.table_abc.foo == self.table_efg.bar)
            .select("*", expr)
        )

        self.assertEqual(
            'SELECT *,RANK() OVER(PARTITION BY "abc"."foo" ORDER BY "efg"."date") '
            'FROM "abc" LEFT JOIN "efg" ON "abc"."foo"="efg"."bar"',
            str(query),
        )

    def test_sum_rows_unbounded_preceeding(self):
        expr = an.Sum(self.table_abc.fizz).over(self.table_abc.foo).orderby(self.table_abc.date).rows(an.Preceding())

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT "
            'SUM("fizz") '
            "OVER("
            'PARTITION BY "foo" ORDER BY "date" '
            "ROWS UNBOUNDED PRECEDING"
            ") "
            'FROM "abc"',
            str(q),
        )

    def test_max_rows_x_preceeding(self):
        expr = an.Max(self.table_abc.fizz).over(self.table_abc.foo).orderby(self.table_abc.date).rows(an.Preceding(5))

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT " 'MAX("fizz") ' "OVER(" 'PARTITION BY "foo" ORDER BY "date" ' "ROWS 5 PRECEDING" ") " 'FROM "abc"',
            str(q),
        )

    def test_min_rows_current_row(self):
        expr = an.Min(self.table_abc.fizz).over(self.table_abc.foo).orderby(self.table_abc.date).rows(an.CURRENT_ROW)

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT " 'MIN("fizz") ' "OVER(" 'PARTITION BY "foo" ORDER BY "date" ' "ROWS CURRENT ROW" ") " 'FROM "abc"',
            str(q),
        )

    def test_varpop_range_unbounded_preceeding(self):
        expr = (
            an.VarPop(self.table_abc.fizz).over(self.table_abc.foo).orderby(self.table_abc.date).range(an.Preceding())
        )

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT "
            'VAR_POP("fizz") '
            "OVER("
            'PARTITION BY "foo" ORDER BY "date" '
            "RANGE UNBOUNDED PRECEDING"
            ") "
            'FROM "abc"',
            str(q),
        )

    def test_max_range_x_preceeding(self):
        expr = an.Max(self.table_abc.fizz).over(self.table_abc.foo).orderby(self.table_abc.date).range(an.Preceding(5))

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT "
            'MAX("fizz") '
            "OVER("
            'PARTITION BY "foo" ORDER BY "date" '
            "RANGE 5 PRECEDING"
            ") "
            'FROM "abc"',
            str(q),
        )

    def test_min_range_current_row(self):
        expr = an.Min(self.table_abc.fizz).over(self.table_abc.foo).orderby(self.table_abc.date).range(an.CURRENT_ROW)

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT "
            'MIN("fizz") '
            "OVER("
            'PARTITION BY "foo" ORDER BY "date" '
            "RANGE CURRENT ROW"
            ") "
            'FROM "abc"',
            str(q),
        )

    def test_variance_rows_between_unbounded_preceeding_unbounded_following(self):
        expr = (
            an.Variance(self.table_abc.fizz)
            .over(self.table_abc.foo)
            .orderby(self.table_abc.date)
            .rows(an.Preceding(), an.Following())
        )

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT "
            'VARIANCE("fizz") '
            "OVER("
            'PARTITION BY "foo" ORDER BY "date" '
            "ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING"
            ") "
            'FROM "abc"',
            str(q),
        )

    def test_first_value_range_between_x_preceeding_unbounded_following(self):
        expr = (
            an.FirstValue(self.table_abc.fizz)
            .over(self.table_abc.foo)
            .orderby(self.table_abc.date)
            .range(an.Preceding(3), an.Following())
        )

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT "
            'FIRST_VALUE("fizz") '
            "OVER("
            'PARTITION BY "foo" ORDER BY "date" '
            "RANGE BETWEEN 3 PRECEDING AND UNBOUNDED FOLLOWING"
            ") "
            'FROM "abc"',
            str(q),
        )

    def test_varpop_rows_between_unbounded_preceeding_x_following(self):
        expr = (
            an.VarPop(self.table_abc.fizz)
            .over(self.table_abc.foo)
            .orderby(self.table_abc.date)
            .rows(an.Preceding(), an.Following(6))
        )

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT "
            'VAR_POP("fizz") '
            "OVER("
            'PARTITION BY "foo" ORDER BY "date" '
            "ROWS BETWEEN UNBOUNDED PRECEDING AND 6 FOLLOWING"
            ") "
            'FROM "abc"',
            str(q),
        )

    def test_count_range_between_unbounded_preceeding_current_row(self):
        expr = (
            an.Count(self.table_abc.fizz)
            .over(self.table_abc.foo)
            .orderby(self.table_abc.date)
            .range(an.Preceding(), an.CURRENT_ROW)
        )

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT "
            'COUNT("fizz") '
            "OVER("
            'PARTITION BY "foo" ORDER BY "date" '
            "RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW"
            ") "
            'FROM "abc"',
            str(q),
        )

    def test_last_value_rows_between_current_row_unbounded_following(self):
        expr = (
            an.LastValue(self.table_abc.fizz)
            .over(self.table_abc.foo)
            .orderby(self.table_abc.date)
            .rows(an.CURRENT_ROW, an.Following())
        )

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT "
            'LAST_VALUE("fizz") '
            "OVER("
            'PARTITION BY "foo" ORDER BY "date" '
            "ROWS BETWEEN CURRENT ROW AND UNBOUNDED FOLLOWING"
            ") "
            'FROM "abc"',
            str(q),
        )

    def test_last_value_rows_between_current_row_unbounded_following_ignore_nulls(self):
        expr = (
            an.LastValue(self.table_abc.fizz)
            .over(self.table_abc.foo)
            .orderby(self.table_abc.date)
            .ignore_nulls()
            .rows(an.CURRENT_ROW, an.Following(8))
        )

        q = Query.from_(self.table_abc).select(expr)

        self.assertEqual(
            "SELECT "
            'LAST_VALUE("fizz" IGNORE NULLS) '
            "OVER("
            'PARTITION BY "foo" ORDER BY "date" '
            "ROWS BETWEEN CURRENT ROW AND 8 FOLLOWING"
            ") "
            'FROM "abc"',
            str(q),
        )

    def test_empty_over(self):
        query = Query.from_(self.table_abc).select(an.Sum(self.table_abc.fizz).over())

        self.assertEqual("SELECT " 'SUM("fizz") OVER() ' 'FROM "abc"', str(query))

    def test_rows_called_twice_raises_attribute_error(self):
        with self.assertRaises(AttributeError):
            an.Sum(self.table_abc.fizz).over(self.table_abc.foo).orderby(self.table_abc.date).rows(an.Preceding()).rows(
                an.Preceding()
            )

    def test_range_called_twice_raises_attribute_error(self):
        with self.assertRaises(AttributeError):
            an.Sum(self.table_abc.fizz).over(self.table_abc.foo).orderby(self.table_abc.date).range(
                an.Preceding()
            ).range(an.Preceding())

    def test_rows_then_range_raises_attribute_error(self):
        with self.assertRaises(AttributeError):
            an.Sum(self.table_abc.fizz).over(self.table_abc.foo).orderby(self.table_abc.date).rows(
                an.Preceding()
            ).range(an.Preceding())

    def test_range_then_rows_raises_attribute_error(self):
        with self.assertRaises(AttributeError):
            an.Sum(self.table_abc.fizz).over(self.table_abc.foo).orderby(self.table_abc.date).range(
                an.Preceding()
            ).rows(an.Preceding())

    def test_lag_generates_correct_sql(self):
        with self.subTest('without partition by'):
            q = Query.from_(self.table_abc).select(
                Lag(self.table_abc.date, 1, '2000-01-01').orderby(self.table_abc.date)
            )

            self.assertEqual('SELECT LAG("date",1,\'2000-01-01\') OVER(ORDER BY "date") FROM "abc"', str(q))

        with self.subTest('with partition by'):
            q = Query.from_(self.table_abc).select(
                Lag(self.table_abc.date, 1, '2000-01-01').over(self.table_abc.foo).orderby(self.table_abc.date)
            )

            self.assertEqual(
                'SELECT LAG("date",1,\'2000-01-01\') OVER(PARTITION BY "foo" ORDER BY "date") FROM "abc"', str(q)
            )

    def test_lead_generates_correct_sql(self):
        with self.subTest('without partition by'):
            q = Query.from_(self.table_abc).select(
                Lead(self.table_abc.date, 1, '2000-01-01').orderby(self.table_abc.date)
            )

            self.assertEqual('SELECT LEAD("date",1,\'2000-01-01\') OVER(ORDER BY "date") FROM "abc"', str(q))

        with self.subTest('with partition by'):
            q = Query.from_(self.table_abc).select(
                Lead(self.table_abc.date, 1, '2000-01-01').over(self.table_abc.foo).orderby(self.table_abc.date)
            )

            self.assertEqual(
                'SELECT LEAD("date",1,\'2000-01-01\') OVER(PARTITION BY "foo" ORDER BY "date") FROM "abc"', str(q)
            )

    def test_qualify(self):
        expr = an.Rank().over(self.table_abc.foo).orderby(self.table_abc.date)
        q = Query.from_(self.table_abc).select("*").qualify(expr > 1)

        self.assertEqual(
            "SELECT " "*" ' FROM "abc" ' 'QUALIFY RANK() OVER(PARTITION BY "foo" ORDER BY "date")>1',
            str(q),
        )

    def test_qualify_and(self):
        expr1 = an.Rank().over(self.table_abc.foo).orderby(self.table_abc.date)
        expr2 = an.RowNumber().over(self.table_abc.foo).orderby(self.table_abc.date)
        q = Query.from_(self.table_abc).select("*").qualify((expr1 > 1) & (expr2 > 2))

        self.assertEqual(
            "SELECT "
            "*"
            ' FROM "abc" '
            'QUALIFY RANK() OVER(PARTITION BY "foo" ORDER BY "date")>1 '
            "AND "
            'ROW_NUMBER() OVER(PARTITION BY "foo" ORDER BY "date")>2',
            str(q),
        )


class NamedWindowTests(unittest.TestCase):
    table_abc = Table("abc")

    def test_named_window_shared_by_analytic_functions(self):
        window = an.Window("w", self.table_abc.foo)

        query = (
            Query.from_(self.table_abc)
            .window(window)
            .select(
                an.Sum(self.table_abc.fizz).over(window),
                an.Count(self.table_abc.fizz).over(window),
                an.Avg(self.table_abc.fizz).over(window),
                an.Min(self.table_abc.fizz).over(window),
                an.Max(self.table_abc.fizz).over(window),
                an.Rank().over(window).orderby(self.table_abc.date),
            )
        )

        self.assertEqual(
            "SELECT "
            'SUM("fizz") OVER w,'
            'COUNT("fizz") OVER w,'
            'AVG("fizz") OVER w,'
            'MIN("fizz") OVER w,'
            'MAX("fizz") OVER w,'
            'RANK() OVER(w ORDER BY "date") '
            'FROM "abc" '
            'WINDOW w AS (PARTITION BY "foo")',
            str(query),
        )

    def test_named_window_chain_adds_order_and_frame(self):
        partition_window = an.Window("partition_window", self.table_abc.foo)
        ordered_window = an.Window("ordered_window").over(partition_window).orderby(self.table_abc.date)
        framed_window = an.Window("framed_window").over(ordered_window).range(an.Preceding(), an.CURRENT_ROW)

        query = (
            Query.from_(self.table_abc)
            .window(framed_window)
            .window(partition_window)
            .window(ordered_window)
            .select(an.Sum(self.table_abc.fizz).over(framed_window))
        )

        self.assertEqual(
            "SELECT "
            'SUM("fizz") OVER framed_window '
            'FROM "abc" '
            'WINDOW partition_window AS (PARTITION BY "foo"),'
            'ordered_window AS (partition_window ORDER BY "date"),'
            'framed_window AS (ordered_window RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)',
            str(query),
        )

    def test_named_window_can_be_used_with_anonymous_window(self):
        named_window = an.Window("named_window", self.table_abc.foo)

        query = (
            Query.from_(self.table_abc)
            .window(named_window)
            .select(
                an.Sum(self.table_abc.fizz).over(named_window),
                an.Rank().over(self.table_abc.bar).orderby(self.table_abc.date),
            )
        )

        self.assertEqual(
            "SELECT "
            'SUM("fizz") OVER named_window,'
            'RANK() OVER(PARTITION BY "bar" ORDER BY "date") '
            'FROM "abc" '
            'WINDOW named_window AS (PARTITION BY "foo")',
            str(query),
        )

    def test_empty_named_window(self):
        window = an.Window("w")

        query = Query.from_(self.table_abc).window(window).select(an.Sum(self.table_abc.fizz).over(window))

        self.assertEqual('SELECT SUM("fizz") OVER w FROM "abc" WINDOW w AS ()', str(query))

    def test_named_window_can_be_defined_and_referenced_by_name(self):
        ordered_window = an.Window("ordered").over("w").orderby(self.table_abc.date)

        query = (
            Query.from_(self.table_abc)
            .window("w", self.table_abc.foo)
            .window(ordered_window)
            .select(an.Sum(self.table_abc.fizz).over("w"), an.Rank().over("ordered"))
        )

        self.assertEqual(
            "SELECT "
            'SUM("fizz") OVER w,'
            'RANK() OVER ordered '
            'FROM "abc" '
            'WINDOW w AS (PARTITION BY "foo"),ordered AS (w ORDER BY "date")',
            str(query),
        )

    def test_named_window_constructor_orderby(self):
        window = an.Window("w", self.table_abc.foo, orderby=self.table_abc.date)

        query = Query.from_(self.table_abc).window(window).select(an.Rank().over(window))

        self.assertEqual(
            'SELECT RANK() OVER w FROM "abc" WINDOW w AS (PARTITION BY "foo" ORDER BY "date")',
            str(query),
        )

    def test_postgresql_and_sqlite_support_named_windows(self):
        select = an.Sum(self.table_abc.fizz).over(an.Window("w", self.table_abc.foo))

        postgresql_query = PostgreSQLQuery.from_(self.table_abc).window(
            an.Window("w", self.table_abc.foo)
        ).select(select)
        sqlite_query = SQLLiteQuery.from_(self.table_abc).window(an.Window("w", self.table_abc.foo)).select(select)

        self.assertEqual(
            'SELECT SUM("fizz") OVER w FROM "abc" WINDOW w AS (PARTITION BY "foo")',
            str(postgresql_query),
        )
        self.assertEqual(
            'SELECT SUM("fizz") OVER w FROM "abc" WINDOW w AS (PARTITION BY "foo")',
            str(sqlite_query),
        )

    def test_other_dialects_reject_named_window_definitions(self):
        with self.assertRaisesRegex(QueryException, "Named windows are not supported"):
            MySQLQuery.from_(self.table_abc).window(an.Window("w", self.table_abc.foo))

    def test_non_select_queries_reject_named_window_definitions(self):
        query = Query.update(self.table_abc).window(an.Window("w")).set(self.table_abc.fizz, 1)

        with self.assertRaisesRegex(QueryException, "only supported in SELECT"):
            str(query)

    def test_unknown_function_window_reference(self):
        window = an.Window("w", self.table_abc.foo)
        query = Query.from_(self.table_abc).select(an.Sum(self.table_abc.fizz).over(window))

        with self.assertRaisesRegex(QueryException, "Unknown window reference: w"):
            str(query)

    def test_unknown_window_definition_reference(self):
        base_window = an.Window("base", self.table_abc.foo)
        dependent_window = an.Window("dependent").over(base_window)
        query = Query.from_(self.table_abc).window(dependent_window).select(
            an.Sum(self.table_abc.fizz).over(dependent_window)
        )

        with self.assertRaisesRegex(QueryException, "Unknown window reference: base"):
            str(query)

    def test_circular_window_references(self):
        first_window = an.Window("first", self.table_abc.foo)
        second_window = an.Window("second").over(first_window)
        first_window = first_window.over(second_window)

        query = Query.from_(self.table_abc).window(first_window).window(second_window).select(
            an.Sum(self.table_abc.fizz).over(first_window)
        )

        with self.assertRaisesRegex(QueryException, "Circular window reference"):
            str(query)

    def test_duplicate_window_names_are_rejected(self):
        with self.assertRaisesRegex(QueryException, "Duplicate window name: w"):
            Query.from_(self.table_abc).window(an.Window("w", self.table_abc.foo)).window(
                an.Window("w", self.table_abc.bar)
            )

    def test_function_cannot_override_partition_order_or_frame(self):
        window = an.Window("w", self.table_abc.foo).orderby(self.table_abc.date).range(
            an.Preceding(), an.CURRENT_ROW
        )

        cases = (
            lambda: an.Sum(self.table_abc.fizz).over(window).partition(self.table_abc.bar),
            lambda: an.Sum(self.table_abc.fizz).over(window).orderby(self.table_abc.date),
            lambda: an.Sum(self.table_abc.fizz).over(window).range(an.Preceding(), an.CURRENT_ROW),
        )

        for case in cases:
            with self.subTest(case=case):
                query = Query.from_(self.table_abc).window(window).select(case())
                with self.assertRaisesRegex(QueryException, "Cannot override"):
                    str(query)

    def test_window_chain_cannot_override_partition_order_or_frame(self):
        base_window = an.Window("base", self.table_abc.foo).orderby(self.table_abc.date).range(
            an.Preceding(), an.CURRENT_ROW
        )

        cases = (
            lambda: an.Window("child").over(base_window).over(self.table_abc.bar),
            lambda: an.Window("child").over(base_window).orderby(self.table_abc.date),
            lambda: an.Window("child").over(base_window).range(an.Preceding(), an.CURRENT_ROW),
        )

        for case in cases:
            with self.subTest(case=case):
                with self.assertRaisesRegex(QueryException, "Cannot override"):
                    child_window = case()
                    query = Query.from_(self.table_abc).window(base_window).window(child_window).select(
                        an.Sum(self.table_abc.fizz).over(child_window)
                    )
                    str(query)

    def test_same_window_name_in_subquery_is_independent_scope(self):
        outer_table = Table("outer_table")
        inner_window = an.Window("w", self.table_abc.foo)
        outer_window = an.Window("w", outer_table.bar)
        inner_query = Query.from_(self.table_abc).window(inner_window).select(
            self.table_abc.id, an.Sum(self.table_abc.fizz).over(inner_window)
        )
        outer_query = Query.from_(inner_query).window(outer_window).select(
            an.Sum(inner_query.fizz).over(outer_window)
        )

        sql = str(outer_query)

        self.assertIn('WINDOW w AS (PARTITION BY "foo")', sql)
        self.assertIn('WINDOW w AS (PARTITION BY "outer_table"."bar")', sql)

    def test_sqlite_named_and_expanded_windows_return_same_results(self):
        rows = [
            ("a", 1, 2),
            ("a", 2, 4),
            ("a", 3, 6),
            ("b", 1, 8),
            ("b", 2, 10),
        ]
        partition_window = an.Window("partition_window", self.table_abc.foo)
        ordered_window = an.Window("ordered_window").over(partition_window).orderby(self.table_abc.date)
        framed_window = an.Window("framed_window").over(ordered_window).range(an.Preceding(), an.CURRENT_ROW)
        named_query = (
            SQLLiteQuery.from_(self.table_abc)
            .window(partition_window)
            .window(ordered_window)
            .window(framed_window)
            .select(
                self.table_abc.foo,
                self.table_abc.date,
                an.Sum(self.table_abc.amount).over(framed_window),
                an.Sum(self.table_abc.amount)
                .over(ordered_window)
                .range(an.Preceding(), an.CURRENT_ROW),
            )
        )
        expanded_query = (
            SQLLiteQuery.from_(self.table_abc)
            .select(
                self.table_abc.foo,
                self.table_abc.date,
                an.Sum(self.table_abc.amount)
                .over(self.table_abc.foo)
                .orderby(self.table_abc.date)
                .range(an.Preceding(), an.CURRENT_ROW),
                an.Sum(self.table_abc.amount)
                .over(self.table_abc.foo)
                .orderby(self.table_abc.date)
                .range(an.Preceding(), an.CURRENT_ROW),
            )
        )

        named_connection = sqlite3.connect(":memory:")
        expanded_connection = sqlite3.connect(":memory:")
        try:
            for connection in (named_connection, expanded_connection):
                connection.execute('CREATE TABLE "abc" ("foo" TEXT, "date" INTEGER, "amount" INTEGER)')
                connection.executemany('INSERT INTO "abc" VALUES (?, ?, ?)', rows)

            named_results = named_connection.execute(str(named_query)).fetchall()
            expanded_results = expanded_connection.execute(str(expanded_query)).fetchall()
        finally:
            named_connection.close()
            expanded_connection.close()

        self.assertEqual(expanded_results, named_results)
        self.assertIsNone(partition_window.frame)
        self.assertIsNone(partition_window.bound)
        self.assertEqual([], partition_window._orderbys)
        self.assertIsNone(ordered_window.frame)
        self.assertIsNone(ordered_window.bound)
