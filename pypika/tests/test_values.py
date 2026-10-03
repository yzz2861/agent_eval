import sqlite3
import unittest

from pypika import Field, MSSQLQuery, PostgreSQLQuery, Query, QmarkParameter, SQLLiteQuery, Table, Values
from pypika.terms import Values as ValuesExpression
from pypika.utils import QueryException


class ValuesRelationTests(unittest.TestCase):
    def test_from_values_with_fields(self):
        values = Values([(1, "a"), (2, "b")], ["id", "name"], alias="temp")

        query = Query.from_(values).select(values.id, values.name).where(values.id > 1)

        self.assertEqual(
            "SELECT \"temp\".\"id\",\"temp\".\"name\" "
            "FROM (VALUES (1,'a'),(2,'b')) \"temp\"(\"id\",\"name\") WHERE \"temp\".\"id\">1",
            str(query),
        )

    def test_join_values_with_fields(self):
        values = Values([(1, "a"), (2, "b")], ["id", "name"], alias="temp")
        table = Table("orders")

        query = Query.from_(table).join(values).on(table.temp_id == values.id).select(table.id, values.name)

        self.assertEqual(
            'SELECT "orders"."id","temp"."name" FROM "orders" '
            "JOIN (VALUES (1,'a'),(2,'b')) \"temp\"(\"id\",\"name\") ON \"orders\".\"temp_id\"=\"temp\".\"id\"",
            str(query),
        )

    def test_values_cte(self):
        values = Values([(1, "a"), (2, "b")], ["id", "name"], alias="temp")

        query = Query.with_(values).from_(values).select(values.id, values.name)

        self.assertEqual(
            "WITH temp(\"id\",\"name\") AS (VALUES (1,'a'),(2,'b')) "
            "SELECT \"temp\".\"id\",\"temp\".\"name\" FROM temp",
            str(query),
        )

    def test_values_cte_with_explicit_name(self):
        values = Values([(1,)], ["id"], alias="temp")

        query = Query.with_(values, "temp").from_(values).select(values.id)

        self.assertEqual("WITH temp(\"id\") AS (VALUES (1)) SELECT \"temp\".\"id\" FROM temp", str(query))

    def test_values_cte_when_with_is_added_after_from(self):
        values = Values([(1,)], ["id"], alias="temp")

        query = Query.from_(values).select(values.id).with_(values)

        self.assertEqual("WITH temp(\"id\") AS (VALUES (1)) SELECT \"temp\".\"id\" FROM temp", str(query))

    def test_postgresql_values(self):
        values = Values([(1, "a")], ["id", "name"], alias="temp")

        query = PostgreSQLQuery.from_(values).select(values.id, values.name)

        self.assertEqual(
            "SELECT \"temp\".\"id\",\"temp\".\"name\" FROM (VALUES (1,'a')) \"temp\"(\"id\",\"name\")",
            str(query),
        )

    def test_mssql_values(self):
        values = Values([(1, "a")], ["id", "name"], alias="temp")

        query = MSSQLQuery.from_(values).select(values.id, values.name)

        self.assertEqual(
            "SELECT \"temp\".\"id\",\"temp\".\"name\" FROM (VALUES (1,'a')) \"temp\"(\"id\",\"name\")",
            str(query),
        )

    def test_sqlite_values(self):
        values = Values([(1, "a")], ["id", "name"], alias="temp")

        query = SQLLiteQuery.from_(values).select(values.id, values.name)

        self.assertEqual(
            "SELECT \"temp\".\"id\",\"temp\".\"name\" "
            "FROM (SELECT \"column1\" \"id\",\"column2\" \"name\" FROM (VALUES (1,'a'))) \"temp\"",
            str(query),
        )

    def test_values_without_column_names_uses_native_names(self):
        values = Values([(1,)], alias="temp")

        postgres_query = PostgreSQLQuery.from_(values).select(values.column1)
        mssql_query = MSSQLQuery.from_(values).select(values.column1)
        sqlite_query = SQLLiteQuery.from_(values).select(values.column1)

        self.assertEqual('SELECT "temp"."column1" FROM (VALUES (1)) "temp"', str(postgres_query))
        self.assertEqual('SELECT "temp"."column1" FROM (VALUES (1)) "temp"', str(mssql_query))
        self.assertEqual('SELECT "temp"."column1" FROM (VALUES (1)) "temp"', str(sqlite_query))

    def test_sqlite_executes_join_against_values(self):
        values = Values([(1, "first"), (2, "second")], ["id", "label"], alias="temp")
        orders = Table("orders")
        query = (
            SQLLiteQuery.from_(orders)
            .join(values)
            .on(orders.temp_id == values.id)
            .select(orders.id, values.label)
            .orderby(orders.id)
        )

        connection = sqlite3.connect(":memory:")
        try:
            connection.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, temp_id INTEGER)")
            connection.executemany("INSERT INTO orders (temp_id) VALUES (?)", [(2,), (1,)])
            rows = connection.execute(str(query)).fetchall()
        finally:
            connection.close()

        self.assertEqual([(1, "second"), (2, "first")], rows)

    def test_parameters_follow_sql_order_and_do_not_accumulate(self):
        values = Values([("a", 1), ("b", 2)], ["label", "id"], alias="temp")
        table = Table("orders")
        query = (
            Query.with_(values)
            .from_(table)
            .join(values)
            .on(table.temp_id == values.id)
            .select(table.id, values.label)
            .where(table.code == "c")
        )

        parameter = QmarkParameter()
        sql = query.get_sql(parameter=parameter)
        self.assertEqual(["a", 1, "b", 2, "c"], parameter.get_parameters())
        self.assertIn("WITH temp(\"label\",\"id\") AS (VALUES (?,?),(?,?))", sql)
        self.assertIn("WHERE \"orders\".\"code\"=?", sql)

        query.get_sql(parameter=parameter)
        self.assertEqual(["a", 1, "b", 2, "c"], parameter.get_parameters())

    def test_raises_for_inconsistent_row_width(self):
        with self.assertRaisesRegex(QueryException, "same number of columns"):
            Values([(1, "a"), (2,)], ["id", "name"], alias="temp")

    def test_raises_for_duplicate_column_names(self):
        with self.assertRaisesRegex(QueryException, "column names must be unique"):
            Values([(1, 2)], ["id", "id"], alias="temp")

    def test_raises_for_empty_values_without_column_information(self):
        with self.assertRaisesRegex(QueryException, "at least one row"):
            Values([])

    def test_relation_requires_alias(self):
        values = Values([(1,)], ["id"])

        with self.assertRaisesRegex(QueryException, "requires an alias"):
            Query.from_(values).select(values[0]).get_sql()

    def test_existing_values_expression_is_unchanged(self):
        self.assertEqual("VALUES(\"id\")", str(ValuesExpression(Field("id"))))


if __name__ == "__main__":
    unittest.main()
