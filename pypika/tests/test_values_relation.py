import sqlite3
import unittest

from pypika import (
    AliasedQuery,
    MSSQLQuery,
    PostgreSQLQuery,
    QmarkParameter,
    Query,
    SQLLiteQuery,
    Table,
    ValuesRelation,
)


class ValuesRelationTests(unittest.TestCase):
    def test_from_with_named_columns_and_alias(self):
        v = ValuesRelation([(1, "a"), (2, "b")], columns=["id", "name"], alias="v")
        q = Query.from_(v).select(v.id, v.name)

        self.assertEqual(
            'SELECT "v"."id","v"."name" FROM (VALUES (1,\'a\'),(2,\'b\')) "v"("id","name")',
            q.get_sql(),
        )

    def test_default_column_names(self):
        v = ValuesRelation([(1, "a"), (2, "b")], alias="v")

        self.assertEqual(["column1", "column2"], v.columns)
        q = Query.from_(v).select(v.column1, v.column2)
        self.assertEqual(
            'SELECT "v"."column1","v"."column2" FROM (VALUES (1,\'a\'),(2,\'b\')) "v"("column1","column2")',
            q.get_sql(),
        )

    def test_join(self):
        users = Table("users")
        v = ValuesRelation([(1, "a"), (2, "b")], columns=["id", "name"], alias="v")
        q = Query.from_(users).join(v).on(users.id == v.id).select(users.id, v.name)

        self.assertEqual(
            'SELECT "users"."id","v"."name" FROM "users" '
            'JOIN (VALUES (1,\'a\'),(2,\'b\')) "v"("id","name") ON "users"."id"="v"."id"',
            q.get_sql(),
        )

    def test_cte(self):
        v = ValuesRelation([(1, "a"), (2, "b")], columns=["id", "name"], alias="v")
        q = Query.with_(v, "data").from_(AliasedQuery("data")).select("*")

        self.assertEqual(
            'WITH data("id","name") AS (VALUES (1,\'a\'),(2,\'b\')) SELECT * FROM data',
            q.get_sql(),
        )

    def test_field_criterion(self):
        v = ValuesRelation([(1, "a"), (2, "b")], columns=["id", "name"], alias="v")
        q = Query.from_(v).select(v.id).where(v.name == "a")

        self.assertEqual(
            'SELECT "v"."id" FROM (VALUES (1,\'a\'),(2,\'b\')) "v"("id","name") WHERE "v"."name"=\'a\'',
            q.get_sql(),
        )

    def test_uneven_row_width_raises(self):
        with self.assertRaises(ValueError):
            ValuesRelation([(1, "a"), (2,)], columns=["id", "name"])

    def test_duplicate_column_names_raise(self):
        with self.assertRaises(ValueError):
            ValuesRelation([(1, "a")], columns=["id", "id"])

    def test_column_count_mismatch_raises(self):
        with self.assertRaises(ValueError):
            ValuesRelation([(1, "a")], columns=["id"])

    def test_empty_rows_without_columns_raise(self):
        with self.assertRaises(ValueError):
            ValuesRelation([])

    def test_empty_rows_with_columns_raise(self):
        with self.assertRaises(ValueError):
            ValuesRelation([], columns=["id", "name"])

    def test_empty_row_values_raise(self):
        with self.assertRaises(ValueError):
            ValuesRelation([()], columns=[])

    def test_parameter_order_and_recompile(self):
        v = ValuesRelation([(1, "a"), (2, "b")], columns=["id", "name"], alias="v")
        q = Query.from_(v).select(v.id).where(v.name == "a")

        parameter = QmarkParameter()
        sql = q.get_sql(parameter=parameter)

        self.assertEqual(
            'SELECT "v"."id" FROM (VALUES (?,?),(?,?)) "v"("id","name") WHERE "v"."name"=?',
            sql,
        )
        self.assertEqual([1, "a", 2, "b", "a"], parameter.get_parameters())

        # Recompiling with a fresh parameter must not accumulate stale values
        parameter2 = QmarkParameter()
        sql2 = q.get_sql(parameter=parameter2)

        self.assertEqual(sql, sql2)
        self.assertEqual([1, "a", 2, "b", "a"], parameter2.get_parameters())


class ValuesRelationDialectTests(unittest.TestCase):
    def setUp(self):
        self.v = ValuesRelation([(1, "a"), (2, "b")], columns=["id", "name"], alias="v")

    def test_postgresql_from(self):
        q = PostgreSQLQuery.from_(self.v).select(self.v.id, self.v.name)

        self.assertEqual(
            'SELECT "v"."id","v"."name" FROM (VALUES (1,\'a\'),(2,\'b\')) "v"("id","name")',
            q.get_sql(),
        )

    def test_postgresql_cte(self):
        q = PostgreSQLQuery.with_(self.v, "data").from_(AliasedQuery("data")).select("*")

        self.assertEqual(
            'WITH data("id","name") AS (VALUES (1,\'a\'),(2,\'b\')) SELECT * FROM data',
            q.get_sql(),
        )

    def test_mssql_from(self):
        q = MSSQLQuery.from_(self.v).select(self.v.id, self.v.name)

        self.assertEqual(
            'SELECT "v"."id","v"."name" FROM (VALUES (1,\'a\'),(2,\'b\')) "v"("id","name")',
            q.get_sql(),
        )

    def test_mssql_cte_wraps_values_in_select(self):
        q = MSSQLQuery.with_(self.v, "data").from_(AliasedQuery("data")).select("*")

        self.assertEqual(
            'WITH data("id","name") AS (SELECT * FROM (VALUES (1,\'a\'),(2,\'b\')) "v"("id","name")) '
            "SELECT * FROM data",
            q.get_sql(),
        )

    def test_sqllite_from_omits_column_name_list(self):
        q = SQLLiteQuery.from_(self.v).select(self.v.id, self.v.name)

        self.assertEqual(
            'SELECT "v"."id","v"."name" FROM (VALUES (1,\'a\'),(2,\'b\')) "v"',
            q.get_sql(),
        )

    def test_sqllite_cte(self):
        q = SQLLiteQuery.with_(self.v, "data").from_(AliasedQuery("data")).select("*")

        self.assertEqual(
            'WITH data("id","name") AS (VALUES (1,\'a\'),(2,\'b\')) SELECT * FROM data',
            q.get_sql(),
        )


class ValuesRelationSQLiteExecutionTests(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(":memory:")

    def tearDown(self):
        self.connection.close()

    def execute(self, sql):
        cursor = self.connection.execute(sql)
        columns = [description[0] for description in cursor.description]
        return columns, cursor.fetchall()

    def test_cte_execution(self):
        v = ValuesRelation([(1, "a"), (2, "b")], columns=["id", "name"], alias="v")
        q = SQLLiteQuery.with_(v, "data").from_(AliasedQuery("data")).select("*")

        columns, rows = self.execute(q.get_sql())

        self.assertEqual(["id", "name"], columns)
        self.assertEqual([(1, "a"), (2, "b")], rows)

    def test_join_execution(self):
        self.connection.execute("CREATE TABLE users (id INTEGER, active INTEGER)")
        self.connection.executemany("INSERT INTO users VALUES (?, ?)", [(1, 1), (2, 0), (3, 1)])

        users = Table("users")
        v = ValuesRelation([(1, "x"), (3, "y")], alias="v")
        q = (
            SQLLiteQuery.from_(users)
            .join(v)
            .on(users.id == v.column1)
            .select(users.id, v.column2)
            .where(users.active == 1)
        )

        columns, rows = self.execute(q.get_sql())

        self.assertEqual(["id", "column2"], columns)
        self.assertEqual([(1, "x"), (3, "y")], rows)

    def test_from_execution_with_default_column_names(self):
        v = ValuesRelation([(1, "a"), (2, "b")], alias="v")
        q = SQLLiteQuery.from_(v).select(v.column1, v.column2).where(v.column1 == 2)

        columns, rows = self.execute(q.get_sql())

        self.assertEqual(["column1", "column2"], columns)
        self.assertEqual([(2, "b")], rows)
