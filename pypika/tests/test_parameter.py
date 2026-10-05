import sqlite3
import unittest
import uuid
from datetime import date
from decimal import Decimal

from pypika import (
    Case,
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


class ParameterTypeTests(unittest.TestCase):
    table_abc = Tables("abc")[0]

    def test_insert_preserves_driver_types(self):
        value_date = date(2024, 2, 22)
        value_uuid = uuid.UUID('12345678-1234-5678-1234-567812345678')
        value_decimal = Decimal('1.23')
        query = (
            Query.into(self.table_abc)
            .columns("a", "b", "c", "d", "e", "f", "g")
            .insert(
                b'bytes',
                bytearray(b'bytearray'),
                value_decimal,
                'null',
                ValueWrapper(None),
                value_date,
                value_uuid,
            )
            .insert(None, None, None, None, None, None, None)
        )

        cases = [
            (QmarkParameter(), list, '?'),
            (FormatParameter(), list, '%s'),
            (NumericParameter(), list, ':'),
            (NamedParameter(), dict, ':param'),
            (PyformatParameter(), dict, '%(param'),
        ]
        expected = [
            b'bytes',
            bytearray(b'bytearray'),
            value_decimal,
            'null',
            None,
            '2024-02-22',
            str(value_uuid),
        ]

        for parameter, collection_type, placeholder in cases:
            with self.subTest(parameter=parameter.__class__.__name__):
                sql = query.get_sql(parameter=parameter)
                params = parameter.get_parameters()
                values = list(params.values()) if collection_type is dict else params
                first_row, second_row = sql.rsplit("),(", 1)

                self.assertEqual(7, first_row.count(placeholder))
                self.assertEqual("null,null,null,null,null,null,null)", second_row)
                self.assertEqual(expected, values)

    def test_sqlite_insert_distinguishes_null_text_null_and_blob(self):
        query = (
            Query.into(self.table_abc)
            .columns("id", "value")
            .insert(1, None)
            .insert(2, 'null')
            .insert(3, b'blob')
            .insert(4, bytearray(b'bytearray'))
            .insert(5, ValueWrapper(None))
        )
        parameter = QmarkParameter()
        sql = query.get_sql(parameter=parameter)

        self.assertEqual(
            'INSERT INTO "abc" ("id","value") VALUES (?,null),(?,?),(?,?),(?,?),(?,?)', sql
        )
        self.assertEqual(
            [1, 2, 'null', 3, b'blob', 4, bytearray(b'bytearray'), 5, None],
            parameter.get_parameters(),
        )

        connection = sqlite3.connect(':memory:')
        try:
            connection.execute('CREATE TABLE "abc" ("id" INTEGER, "value")')
            connection.execute(sql, parameter.get_parameters())
            rows = connection.execute(
                'SELECT "id", "value", typeof("value") FROM "abc" ORDER BY "id"'
            ).fetchall()
        finally:
            connection.close()

        self.assertEqual(
            [
                (1, None, 'null'),
                (2, 'null', 'text'),
                (3, b'blob', 'blob'),
                (4, b'bytearray', 'blob'),
                (5, None, 'null'),
            ],
            rows,
        )

    def test_update_and_conditions_preserve_driver_types(self):
        value_decimal = Decimal('1.23')
        value_bytes = b'bytes'
        value_bytearray = bytearray(b'bytearray')
        query = (
            Query.update(self.table_abc)
            .set("bytes", value_bytes)
            .set("bytearray", value_bytearray)
            .set("decimal", value_decimal)
            .set("explicit_null", ValueWrapper(None))
            .where(self.table_abc.bytes == value_bytes)
            .where(self.table_abc.bytearray == value_bytearray)
            .where(self.table_abc.decimal == value_decimal)
            .where(self.table_abc.explicit_null == ValueWrapper(None))
        )

        parameter = FormatParameter()
        sql = query.get_sql(parameter=parameter)
        expected = [
            value_bytes,
            value_bytearray,
            value_decimal,
            None,
            value_bytes,
            value_bytearray,
            value_decimal,
            None,
        ]

        self.assertEqual(8, sql.count('%s'))
        self.assertEqual(expected, parameter.get_parameters())

    def test_explicit_parameter_value_wrapper_preserves_driver_types(self):
        value_decimal = Decimal('1.23')
        values = [b'bytes', bytearray(b'bytearray'), value_decimal, None]
        names = ['bytes', 'bytearray', 'decimal', 'explicit_null']
        parameter_cases = [
            (QmarkParameter, '?'),
            (FormatParameter, '%s'),
            (NumericParameter, ':'),
            (NamedParameter, ':'),
            (PyformatParameter, '%('),
        ]

        for parameter_cls, expected_placeholder in parameter_cases:
            query = Query.update(self.table_abc)
            for name, value in zip(names, values):
                query = query.set(name, ParameterValueWrapper(parameter_cls(name), value))

            with self.subTest(parameter=parameter_cls.__name__):
                parameter = parameter_cls()
                sql = query.get_sql(parameter=parameter)

                self.assertEqual(4, sql.count(expected_placeholder))
                if expected_placeholder == ':':
                    self.assertIn(':bytes', sql)
                params = parameter.get_parameters()
                if isinstance(params, dict):
                    for name, value in zip(names, values):
                        self.assertIs(value, params[name])
                else:
                    self.assertEqual(values, params)

    def test_conditional_expression_preserves_driver_types(self):
        value_decimal = Decimal('1.23')
        value_bytes = b'bytes'
        value_bytearray = bytearray(b'bytearray')
        value_none = None
        expression = (
            Case()
            .when(self.table_abc.kind == 'bytes', value_bytes)
            .when(self.table_abc.kind == 'bytearray', value_bytearray)
            .when(self.table_abc.kind == 'decimal', value_decimal)
            .else_(ValueWrapper(value_none))
        )
        query = Query.from_(self.table_abc).select(expression).where(self.table_abc.decimal == value_decimal)

        parameter = QmarkParameter()
        sql = query.get_sql(parameter=parameter)

        self.assertEqual(
            'SELECT CASE WHEN "kind"=? THEN ? WHEN "kind"=? THEN ? WHEN "kind"=? THEN ? ELSE ? END '
            'FROM "abc" WHERE "decimal"=?',
            sql,
        )
        self.assertEqual(
            [
                'bytes',
                value_bytes,
                'bytearray',
                value_bytearray,
                'decimal',
                value_decimal,
                value_none,
                value_decimal,
            ],
            parameter.get_parameters(),
        )

    def test_literal_values_remain_inline(self):
        value_date = date(2024, 2, 22)
        value_uuid = uuid.UUID('12345678-1234-5678-1234-567812345678')
        query = (
            Query.into(self.table_abc)
            .columns("bytes", "bytearray", "decimal", "date", "uuid", "null")
            .insert(b'bytes', bytearray(b'bytearray'), Decimal('1.23'), value_date, value_uuid, None)
        )

        self.assertEqual(
            'INSERT INTO "abc" ("bytes","bytearray","decimal","date","uuid","null") '
            "VALUES (b'bytes',bytearray(b'bytearray'),1.23,'2024-02-22','12345678-1234-5678-1234-567812345678',null)",
            str(query),
        )
