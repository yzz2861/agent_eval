import sqlite3
import unittest
import uuid
from datetime import date
from decimal import Decimal

from pypika import (
    FormatParameter,
    NamedParameter,
    NumericParameter,
    Parameter,
    PyformatParameter,
    QmarkParameter,
    Query,
    Tables,
)
from pypika.terms import ListParameter, ParameterValueWrapper, ValueWrapper


class CapturingCursor:
    def __init__(self):
        self.calls = []

    def execute(self, operation, parameters=()):
        self.calls.append((operation, parameters))


class ParametrizedTests(unittest.TestCase):
    table_abc, table_efg = Tables("abc", "efg")

    def test_param_insert(self):
        q = Query.into(self.table_abc).columns("a", "b", "c").insert(Parameter("?"), Parameter("?"), Parameter("?"))

        self.assertEqual('INSERT INTO "abc" ("a","b","c") VALUES (?,?,?)', q.get_sql())

    def test_param_select_join(self):
        q = (
            Query.from_(self.table_abc)
            .select("*")
            .where(self.table_abc.category == Parameter("%s"))
            .join(self.table_efg)
            .on(self.table_abc.id == self.table_efg.abc_id)
            .where(self.table_efg.date >= Parameter("%s"))
            .limit(10)
        )

        self.assertEqual(
            'SELECT * FROM "abc" JOIN "efg" ON "abc"."id"="efg"."abc_id" WHERE "abc"."category"=%s AND "efg"."date">=%s LIMIT 10',
            q.get_sql(),
        )

    def test_param_select_subquery(self):
        q = (
            Query.from_(self.table_abc)
            .select("*")
            .where(self.table_abc.category == Parameter("&1"))
            .where(
                self.table_abc.id.isin(
                    Query.from_(self.table_efg)
                    .select(self.table_efg.abc_id)
                    .where(self.table_efg.date >= Parameter("&2"))
                )
            )
            .limit(10)
        )

        self.assertEqual(
            'SELECT * FROM "abc" WHERE "category"=&1 AND "id" IN (SELECT "abc_id" FROM "efg" WHERE "date">=&2) LIMIT 10',
            q.get_sql(),
        )

    def test_join(self):
        subquery = (
            Query.from_(self.table_efg)
            .select(self.table_efg.fiz, self.table_efg.buz)
            .where(self.table_efg.buz == Parameter(":buz"))
        )

        q = (
            Query.from_(self.table_abc)
            .join(subquery)
            .on(self.table_abc.bar == subquery.buz)
            .select(self.table_abc.foo, subquery.fiz)
            .where(self.table_abc.bar == Parameter(":bar"))
        )

        self.assertEqual(
            'SELECT "abc"."foo","sq0"."fiz" FROM "abc" JOIN (SELECT "fiz","buz" FROM "efg" WHERE "buz"=:buz)'
            ' "sq0" ON "abc"."bar"="sq0"."buz" WHERE "abc"."bar"=:bar',
            q.get_sql(),
        )

    def test_qmark_parameter(self):
        self.assertEqual('?', QmarkParameter().get_sql())

    def test_numeric_parameter(self):
        self.assertEqual(':14', NumericParameter('14').get_sql())
        self.assertEqual(':15', NumericParameter(15).get_sql())

    def test_named_parameter(self):
        self.assertEqual(':buz', NamedParameter('buz').get_sql())

    def test_format_parameter(self):
        self.assertEqual('%s', FormatParameter().get_sql())

    def test_pyformat_parameter(self):
        self.assertEqual('%(buz)s', PyformatParameter('buz').get_sql())


class ParametrizedTestsWithValues(unittest.TestCase):
    table_abc, table_efg = Tables("abc", "efg")

    def assert_sql_and_parameters(self, query, parameter, expected_sql, expected_parameters):
        sql = query.get_sql(parameter=parameter)
        self.assertEqual(expected_sql, sql)
        self.assertEqual(expected_parameters, parameter.get_parameters())

    def test_param_insert(self):
        q = Query.into(self.table_abc).columns("a", "b", "c").insert(1, 2.2, 'foo')

        parameter = QmarkParameter()
        sql = q.get_sql(parameter=parameter)
        self.assertEqual('INSERT INTO "abc" ("a","b","c") VALUES (?,?,?)', sql)
        self.assertEqual([1, 2.2, 'foo'], parameter.get_parameters())

    def test_param_select_join(self):
        q = (
            Query.from_(self.table_abc)
            .select("*")
            .where(self.table_abc.category == 'foobar')
            .join(self.table_efg)
            .on(self.table_abc.id == self.table_efg.abc_id)
            .where(self.table_efg.date >= date(2024, 2, 22))
            .limit(10)
        )

        parameter = FormatParameter()
        sql = q.get_sql(parameter=parameter)
        self.assertEqual(
            'SELECT * FROM "abc" JOIN "efg" ON "abc"."id"="efg"."abc_id" WHERE "abc"."category"=%s AND "efg"."date">=%s LIMIT 10',
            sql,
        )
        self.assertEqual(['foobar', '2024-02-22'], parameter.get_parameters())

    def test_param_select_subquery(self):
        q = (
            Query.from_(self.table_abc)
            .select("*")
            .where(self.table_abc.category == 'foobar')
            .where(
                self.table_abc.id.isin(
                    Query.from_(self.table_efg)
                    .select(self.table_efg.abc_id)
                    .where(self.table_efg.date >= date(2024, 2, 22))
                )
            )
            .limit(10)
        )

        parameter = ListParameter(placeholder=lambda idx: f'&{idx+1}')
        sql = q.get_sql(parameter=parameter)
        self.assertEqual(
            'SELECT * FROM "abc" WHERE "category"=&1 AND "id" IN (SELECT "abc_id" FROM "efg" WHERE "date">=&2) LIMIT 10',
            sql,
        )
        self.assertEqual(['foobar', '2024-02-22'], parameter.get_parameters())

    def test_join(self):
        subquery = (
            Query.from_(self.table_efg)
            .select(self.table_efg.fiz, self.table_efg.buz)
            .where(self.table_efg.buz == 'buz')
        )

        q = (
            Query.from_(self.table_abc)
            .join(subquery)
            .on(self.table_abc.bar == subquery.buz)
            .select(self.table_abc.foo, subquery.fiz)
            .where(self.table_abc.bar == 'bar')
        )

        parameter = NamedParameter()
        sql = q.get_sql(parameter=parameter)
        self.assertEqual(
            'SELECT "abc"."foo","sq0"."fiz" FROM "abc" JOIN (SELECT "fiz","buz" FROM "efg" WHERE "buz"=:param1)'
            ' "sq0" ON "abc"."bar"="sq0"."buz" WHERE "abc"."bar"=:param2',
            sql,
        )
        self.assertEqual({'param1': 'buz', 'param2': 'bar'}, parameter.get_parameters())

    def test_join_with_parameter_value_wrapper(self):
        subquery = (
            Query.from_(self.table_efg)
            .select(self.table_efg.fiz, self.table_efg.buz)
            .where(self.table_efg.buz == ParameterValueWrapper(Parameter(':buz'), 'buz'))
        )

        q = (
            Query.from_(self.table_abc)
            .join(subquery)
            .on(self.table_abc.bar == subquery.buz)
            .select(self.table_abc.foo, subquery.fiz)
            .where(self.table_abc.bar == ParameterValueWrapper(NamedParameter('bar'), 'bar'))
        )

        parameter = NamedParameter()
        sql = q.get_sql(parameter=parameter)
        self.assertEqual(
            'SELECT "abc"."foo","sq0"."fiz" FROM "abc" JOIN (SELECT "fiz","buz" FROM "efg" WHERE "buz"=:buz)'
            ' "sq0" ON "abc"."bar"="sq0"."buz" WHERE "abc"."bar"=:bar',
            sql,
        )
        self.assertEqual({':buz': 'buz', 'bar': 'bar'}, parameter.get_parameters())

    def test_pyformat_parameter(self):
        q = Query.into(self.table_abc).columns("a", "b", "c").insert(1, 2.2, 'foo')

        parameter = PyformatParameter()
        sql = q.get_sql(parameter=parameter)
        self.assertEqual('INSERT INTO "abc" ("a","b","c") VALUES (%(param1)s,%(param2)s,%(param3)s)', sql)
        self.assertEqual({"param1": 1, "param2": 2.2, "param3": "foo"}, parameter.get_parameters())

    def test_native_types_in_multirow_insert(self):
        first_blob = b"first blob"
        first_mutable_blob = bytearray(b"first mutable blob")
        first_amount = Decimal("1.5")
        second_blob = b"second blob"
        second_mutable_blob = bytearray(b"second mutable blob")
        second_amount = Decimal("2.5")

        q = (
            Query.into(self.table_abc)
            .columns("literal_null", "bound_null", "text_null", "blob", "mutable_blob", "amount")
            .insert(
                (None, ValueWrapper(None), "null", first_blob, first_mutable_blob, first_amount),
                (None, ValueWrapper(None), "null", second_blob, second_mutable_blob, second_amount),
            )
        )

        parameter = QmarkParameter()
        sql = q.get_sql(parameter=parameter)
        self.assertEqual(
            'INSERT INTO "abc" ("literal_null","bound_null","text_null","blob","mutable_blob","amount") '
            "VALUES (null,?,?,?,?,?),(null,?,?,?,?,?)",
            sql,
        )
        self.assertEqual(
            [
                None,
                "null",
                first_blob,
                first_mutable_blob,
                first_amount,
                None,
                "null",
                second_blob,
                second_mutable_blob,
                second_amount,
            ],
            parameter.get_parameters(),
        )

    def test_native_types_in_update_and_conditions(self):
        blob = b"blob"
        mutable_blob = bytearray(b"mutable blob")
        amount = Decimal("1.5")

        q = (
            Query.update(self.table_abc)
            .set("blob", blob)
            .set("mutable_blob", mutable_blob)
            .set("amount", amount)
            .set("bound_null", ValueWrapper(None))
            .where(self.table_abc.blob == blob)
            .where(self.table_abc.mutable_blob == mutable_blob)
            .where(self.table_abc.amount == amount)
        )

        parameter = QmarkParameter()
        sql = q.get_sql(parameter=parameter)
        self.assertEqual(
            'UPDATE "abc" SET "blob"=?,"mutable_blob"=?,"amount"=?,"bound_null"=? '
            'WHERE "blob"=? AND "mutable_blob"=? AND "amount"=?',
            sql,
        )
        parameters = parameter.get_parameters()
        self.assertEqual(
            [blob, mutable_blob, amount, None, blob, mutable_blob, amount],
            parameters,
        )
        self.assertTrue(all(isinstance(value, bytes) for value in (parameters[0], parameters[4])))
        self.assertTrue(all(isinstance(value, bytearray) for value in (parameters[1], parameters[5])))
        self.assertTrue(all(isinstance(value, Decimal) for value in (parameters[2], parameters[6])))
        self.assertIsNone(parameters[3])

    def test_native_types_in_between_condition(self):
        lower = Decimal("1.5")
        upper = Decimal("2.5")
        q = Query.from_(self.table_abc).select("*").where(self.table_abc.amount[lower:upper])

        parameter = QmarkParameter()
        sql = q.get_sql(parameter=parameter)
        self.assertEqual('SELECT * FROM "abc" WHERE "amount" BETWEEN ? AND ?', sql)
        self.assertEqual([lower, upper], parameter.get_parameters())

    def test_decimal_parameters_with_capturing_cursor(self):
        amount = Decimal("1.5")
        q = Query.update(self.table_abc).set("amount", amount).where(self.table_abc.amount == amount)
        parameter = QmarkParameter()
        cursor = CapturingCursor()

        cursor.execute(q.get_sql(parameter=parameter), parameter.get_parameters())

        self.assertEqual(
            [
                (
                    'UPDATE "abc" SET "amount"=? WHERE "amount"=?',
                    [amount, amount],
                )
            ],
            cursor.calls,
        )
        self.assertTrue(all(isinstance(value, Decimal) for value in cursor.calls[0][1]))

    def test_sqlite_distinguishes_null_text_null_and_blob(self):
        blob = b"blob value"
        mutable_blob = bytearray(b"mutable blob value")
        q = (
            Query.into(self.table_abc)
            .columns("literal_null", "bound_null", "text_null", "blob", "mutable_blob")
            .insert(None, ValueWrapper(None), "null", blob, mutable_blob)
        )
        parameter = QmarkParameter()
        sql = q.get_sql(parameter=parameter)

        connection = sqlite3.connect(":memory:")
        try:
            connection.execute("CREATE TABLE abc (literal_null, bound_null, text_null, blob, mutable_blob)")
            connection.execute(sql, parameter.get_parameters())
            row = connection.execute(
                "SELECT "
                "typeof(literal_null), typeof(bound_null), typeof(text_null), typeof(blob), typeof(mutable_blob), "
                "literal_null, bound_null, text_null, blob, mutable_blob "
                "FROM abc"
            ).fetchone()
        finally:
            connection.close()

        self.assertEqual(("null", "null", "text", "blob", "blob"), row[:5])
        self.assertEqual((None, None, "null", blob, bytes(mutable_blob)), row[5:])

    def test_parameter_value_wrapper_keeps_native_types(self):
        values = [None, b"blob", bytearray(b"mutable blob"), Decimal("1.5")]

        for value in values:
            with self.subTest(type=type(value).__name__):
                parameter = QmarkParameter()
                q = Query.into(self.table_abc).insert(ParameterValueWrapper(parameter, value))
                sql = q.get_sql(parameter=parameter)
                self.assertEqual('INSERT INTO "abc" VALUES (?)', sql)
                self.assertEqual([value], parameter.get_parameters())

    def test_explicit_parameter_value_wrapper_across_placeholder_styles(self):
        value = Decimal("1.5")
        parameter_styles = [
            (QmarkParameter(), QmarkParameter(), 'INSERT INTO "abc" VALUES (?)', [value]),
            (NumericParameter(), Parameter(":1"), 'INSERT INTO "abc" VALUES (:1)', [value]),
            (FormatParameter(), Parameter("%s"), 'INSERT INTO "abc" VALUES (%s)', [value]),
            (
                ListParameter(placeholder=lambda index: f"&{index + 1}"),
                Parameter("&1"),
                'INSERT INTO "abc" VALUES (&1)',
                [value],
            ),
            (
                NamedParameter(),
                NamedParameter("amount"),
                'INSERT INTO "abc" VALUES (:amount)',
                {"amount": value},
            ),
            (
                PyformatParameter(),
                PyformatParameter("amount"),
                'INSERT INTO "abc" VALUES (%(amount)s)',
                {"amount": value},
            ),
        ]

        for parameter, explicit_parameter, expected_sql, expected_parameters in parameter_styles:
            with self.subTest(parameter=type(parameter).__name__):
                query = Query.into(self.table_abc).insert(ParameterValueWrapper(explicit_parameter, value))
                self.assert_sql_and_parameters(query, parameter, expected_sql, expected_parameters)

    def test_native_types_across_placeholder_styles(self):
        value = Decimal("1.5")
        query = Query.from_(self.table_abc).select("*").where(self.table_abc.amount == value)
        parameter_styles = [
            (QmarkParameter(), 'SELECT * FROM "abc" WHERE "amount"=?', [value]),
            (NumericParameter(), 'SELECT * FROM "abc" WHERE "amount"=:1', [value]),
            (FormatParameter(), 'SELECT * FROM "abc" WHERE "amount"=%s', [value]),
            (
                ListParameter(placeholder=lambda index: f"&{index + 1}"),
                'SELECT * FROM "abc" WHERE "amount"=&1',
                [value],
            ),
            (NamedParameter(), 'SELECT * FROM "abc" WHERE "amount"=:param1', {"param1": value}),
            (PyformatParameter(), 'SELECT * FROM "abc" WHERE "amount"=%(param1)s', {"param1": value}),
        ]

        for parameter, expected_sql, expected_parameters in parameter_styles:
            with self.subTest(parameter=type(parameter).__name__):
                self.assert_sql_and_parameters(query, parameter, expected_sql, expected_parameters)

    def test_date_and_uuid_parameter_conversions_remain_consistent(self):
        special_values = [
            (date(2024, 2, 22), "2024-02-22"),
            (uuid.UUID("12345678-1234-5678-1234-567812345678"), "12345678-1234-5678-1234-567812345678"),
        ]

        for value, expected in special_values:
            with self.subTest(type=type(value).__name__):
                insert = Query.into(self.table_abc).insert(value)
                parameter = QmarkParameter()
                self.assertEqual('INSERT INTO "abc" VALUES (?)', insert.get_sql(parameter=parameter))
                self.assertEqual([expected], parameter.get_parameters())

                update = Query.update(self.table_abc).set("value", value).where(self.table_abc.value == value)
                parameter = QmarkParameter()
                self.assertEqual(
                    'UPDATE "abc" SET "value"=? WHERE "value"=?',
                    update.get_sql(parameter=parameter),
                )
                self.assertEqual([expected, expected], parameter.get_parameters())

    def test_literal_generation_remains_unchanged(self):
        self.assertEqual("null", ValueWrapper(None).get_sql())
        self.assertEqual("1.5", ValueWrapper(Decimal("1.5")).get_sql())
        self.assertEqual("b'blob'", ValueWrapper(b"blob").get_sql())
        self.assertEqual("bytearray(b'mutable blob')", ValueWrapper(bytearray(b"mutable blob")).get_sql())
