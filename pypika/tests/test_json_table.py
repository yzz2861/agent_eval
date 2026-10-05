import unittest

from pypika import (
    JSONTable,
    JSONTableDefault,
    JSONTableExistsColumn,
    JSONTableNested,
    JSONTableOnEmptyError,
    JSONTableOrdinalityColumn,
    JSONTablePathColumn,
    MySQLQuery,
    Parameter,
    PostgreSQLQuery,
    QmarkParameter,
    Query,
    QueryException,
    Table,
)
from pypika.utils import DialectNotSupported


class JSONTableSQLTests(unittest.TestCase):
    def test_official_mysql_example(self):
        # https://dev.mysql.com/doc/refman/8.0/en/json-table-functions.html
        jt = JSONTable(
            '[{"a":"3"},{"a":2},{"b":1},{"a":0},{"a":[1,2]}]',
            "$[*]",
            columns=[
                JSONTableOrdinalityColumn("rowid"),
                JSONTablePathColumn(
                    "ac",
                    "VARCHAR(100)",
                    "$.a",
                    on_empty=JSONTableDefault("111"),
                    on_error=JSONTableDefault("999"),
                ),
                JSONTablePathColumn("aj", "JSON", "$.a", on_empty=JSONTableDefault('{"x": 333}')),
                JSONTableExistsColumn("bx", "INT", "$.b"),
            ],
            alias="tt",
        )
        q = MySQLQuery.from_(jt).select("*")

        self.assertEqual(
            """SELECT * FROM JSON_TABLE('[{"a":"3"},{"a":2},{"b":1},{"a":0},{"a":[1,2]}]', """
            """'$[*]' COLUMNS (`rowid` FOR ORDINALITY,"""
            """`ac` VARCHAR(100) PATH '$.a' DEFAULT '111' ON EMPTY DEFAULT '999' ON ERROR,"""
            """`aj` JSON PATH '$.a' DEFAULT '{"x": 333}' ON EMPTY,"""
            """`bx` INT EXISTS PATH '$.b')) `tt`""",
            str(q),
        )

    def test_official_nested_path_example(self):
        jt = JSONTable(
            '[{"a": 1, "b": [11,111]}, {"a": 2, "b": [22,222]}, {"a":3}]',
            "$[*]",
            columns=[
                JSONTablePathColumn("a", "INT", "$.a"),
                JSONTableNested("$.b[*]", columns=[JSONTablePathColumn("b", "INT", "$")]),
            ],
            alias="t",
        )
        q = MySQLQuery.from_(jt).select("*")

        self.assertEqual(
            """SELECT * FROM JSON_TABLE('[{"a": 1, "b": [11,111]}, {"a": 2, "b": [22,222]}, {"a":3}]', """
            """'$[*]' COLUMNS (`a` INT PATH '$.a',NESTED PATH '$.b[*]' COLUMNS (`b` INT PATH '$'))) `t`""",
            str(q),
        )

    def test_multi_level_nested_path(self):
        jt = JSONTable(
            '[{"a": 1, "b": [{"c": [10, 20]}]}]',
            "$[*]",
            columns=[
                JSONTablePathColumn("a", "INT", "$.a"),
                JSONTableNested(
                    "$.b[*]",
                    columns=[
                        JSONTablePathColumn("b", "JSON", "$"),
                        JSONTableNested("$.c[*]", columns=[JSONTablePathColumn("c", "INT", "$")]),
                    ],
                ),
            ],
            alias="jt",
        )
        q = MySQLQuery.from_(jt).select(jt.a, jt.b, jt.c)

        self.assertEqual(
            """SELECT `jt`.`a`,`jt`.`b`,`jt`.`c` FROM JSON_TABLE('[{"a": 1, "b": [{"c": [10, 20]}]}]', """
            """'$[*]' COLUMNS (`a` INT PATH '$.a',"""
            """NESTED PATH '$.b[*]' COLUMNS (`b` JSON PATH '$',"""
            """NESTED PATH '$.c[*]' COLUMNS (`c` INT PATH '$')))) `jt`""",
            str(q),
        )

    def test_on_empty_on_error_options(self):
        jt = JSONTable(
            '[{"a": 1}]',
            "$[*]",
            columns=[
                JSONTablePathColumn(
                    "a",
                    "INT",
                    "$.a",
                    on_empty=JSONTableOnEmptyError.NULL,
                    on_error=JSONTableOnEmptyError.ERROR,
                ),
                JSONTablePathColumn("b", "INT", "$.b", on_empty=JSONTableOnEmptyError.ERROR),
                JSONTablePathColumn("c", "INT", "$.c", on_error=JSONTableDefault("0")),
            ],
            alias="jt",
        )
        q = MySQLQuery.from_(jt).select("*")

        self.assertEqual(
            """SELECT * FROM JSON_TABLE('[{"a": 1}]', '$[*]' COLUMNS ("""
            """`a` INT PATH '$.a' NULL ON EMPTY ERROR ON ERROR,"""
            """`b` INT PATH '$.b' ERROR ON EMPTY,"""
            """`c` INT PATH '$.c' DEFAULT '0' ON ERROR)) `jt`""",
            str(q),
        )

    def test_fields_in_select_and_where(self):
        jt = JSONTable(
            '[{"a": 1}, {"a": 2}]',
            "$[*]",
            columns=[JSONTablePathColumn("a", "INT", "$.a")],
            alias="jt",
        )
        q = MySQLQuery.from_(jt).select(jt.a).where(jt.a > 1)

        self.assertEqual(
            """SELECT `jt`.`a` FROM JSON_TABLE('[{"a": 1}, {"a": 2}]', '$[*]' COLUMNS (`a` INT PATH '$.a')) `jt` """
            """WHERE `jt`.`a`>1""",
            str(q),
        )

    def test_join(self):
        orders = Table("orders")
        jt = JSONTable(
            '[{"id": 1}, {"id": 2}]',
            "$[*]",
            columns=[JSONTablePathColumn("order_id", "INT", "$.id")],
            alias="jt",
        )
        q = (
            MySQLQuery.from_(orders)
            .join(jt)
            .on(jt.order_id == orders.id)
            .select(orders.id, jt.order_id)
            .where(jt.order_id > 1)
        )

        self.assertEqual(
            """SELECT `orders`.`id`,`jt`.`order_id` FROM `orders` """
            """JOIN JSON_TABLE('[{"id": 1}, {"id": 2}]', '$[*]' COLUMNS (`order_id` INT PATH '$.id')) `jt` """
            """ON `jt`.`order_id`=`orders`.`id` WHERE `jt`.`order_id`>1""",
            str(q),
        )

    def test_field_as_json_document(self):
        orders = Table("orders")
        jt = JSONTable(
            orders.doc,
            "$[*]",
            columns=[JSONTablePathColumn("a", "INT", "$.a")],
            alias="jt",
        )
        q = MySQLQuery.from_(orders).join(jt).on(jt.a == orders.id).select(orders.id, jt.a)

        self.assertEqual(
            """SELECT `orders`.`id`,`jt`.`a` FROM `orders` """
            """JOIN JSON_TABLE(`orders`.`doc`, '$[*]' COLUMNS (`a` INT PATH '$.a')) `jt` """
            """ON `jt`.`a`=`orders`.`id`""",
            str(q),
        )

    def test_generic_query_without_dialect(self):
        jt = JSONTable(
            '[{"a": 1}]',
            "$[*]",
            columns=[JSONTablePathColumn("a", "INT", "$.a")],
            alias="jt",
        )
        q = Query.from_(jt).select(jt.a)

        self.assertEqual(
            """SELECT "jt"."a" FROM JSON_TABLE('[{"a": 1}]', '$[*]' COLUMNS ("a" INT PATH '$.a')) "jt" """.rstrip(),
            str(q),
        )

    def test_standalone_node_sql(self):
        jt = JSONTable(
            '[1, 2]',
            "$[*]",
            columns=[JSONTableOrdinalityColumn("rowid")],
            alias="jt",
        )

        self.assertEqual("""JSON_TABLE('[1, 2]', '$[*]' COLUMNS ("rowid" FOR ORDINALITY)) "jt" """.rstrip(), str(jt))


class JSONTableQuotingTests(unittest.TestCase):
    def test_quote_escaping(self):
        jt = JSONTable(
            """{"a": "it's"}""",
            '$."it\'s"',
            columns=[
                JSONTablePathColumn(
                    "a",
                    "VARCHAR(100)",
                    '$."it\'s"',
                    on_empty=JSONTableDefault("""{"x": "it's"}"""),
                )
            ],
            alias="jt",
        )
        q = MySQLQuery.from_(jt).select(jt.a)

        self.assertEqual(
            """SELECT `jt`.`a` FROM JSON_TABLE('{"a": "it''s"}', '$."it''s"' COLUMNS """
            """(`a` VARCHAR(100) PATH '$."it''s"' DEFAULT '{"x": "it''s"}' ON EMPTY)) `jt`""",
            str(q),
        )


class JSONTableParameterTests(unittest.TestCase):
    def test_parameter_as_json_document(self):
        jt = JSONTable(
            Parameter("%s"),
            "$[*]",
            columns=[JSONTablePathColumn("a", "INT", "$.a")],
            alias="jt",
        )
        q = MySQLQuery.from_(jt).select(jt.a)

        self.assertEqual(
            """SELECT `jt`.`a` FROM JSON_TABLE(%s, '$[*]' COLUMNS (`a` INT PATH '$.a')) `jt`""",
            str(q),
        )

    def test_parameter_order(self):
        jt = JSONTable(
            '[{"a": 1}]',
            "$[*]",
            columns=[JSONTablePathColumn("a", "INT", "$.a")],
            alias="jt",
        )
        parameter = QmarkParameter()
        q = MySQLQuery.from_(jt).select(jt.a).where(jt.a == 5)

        self.assertEqual(
            """SELECT `jt`.`a` FROM JSON_TABLE(?, '$[*]' COLUMNS (`a` INT PATH '$.a')) `jt` WHERE `jt`.`a`=?""",
            q.get_sql(parameter=parameter),
        )
        self.assertEqual(['[{"a": 1}]', 5], parameter.get_parameters())


class JSONTableValidationTests(unittest.TestCase):
    def test_alias_required(self):
        with self.assertRaises(QueryException):
            JSONTable("[]", "$[*]", columns=[JSONTableOrdinalityColumn("rowid")])

    def test_columns_required(self):
        with self.assertRaises(QueryException):
            JSONTable("[]", "$[*]", columns=[], alias="jt")

    def test_path_required(self):
        with self.assertRaises(QueryException):
            JSONTable("[]", "", columns=[JSONTableOrdinalityColumn("rowid")], alias="jt")

    def test_raw_string_column_rejected(self):
        with self.assertRaises(QueryException):
            JSONTable("[]", "$[*]", columns=["a INT PATH '$.a'"], alias="jt")

    def test_duplicate_column_names(self):
        with self.assertRaises(QueryException):
            JSONTable(
                "[]",
                "$[*]",
                columns=[
                    JSONTablePathColumn("a", "INT", "$.a"),
                    JSONTablePathColumn("a", "INT", "$.b"),
                ],
                alias="jt",
            )

    def test_duplicate_column_names_case_insensitive(self):
        with self.assertRaises(QueryException):
            JSONTable(
                "[]",
                "$[*]",
                columns=[
                    JSONTablePathColumn("a", "INT", "$.a"),
                    JSONTableExistsColumn("A", "INT", "$.b"),
                ],
                alias="jt",
            )

    def test_duplicate_column_names_across_nested_levels(self):
        with self.assertRaises(QueryException):
            JSONTable(
                "[]",
                "$[*]",
                columns=[
                    JSONTablePathColumn("a", "INT", "$.a"),
                    JSONTableNested("$.b[*]", columns=[JSONTablePathColumn("a", "INT", "$")]),
                ],
                alias="jt",
            )

    def test_type_required(self):
        for invalid_type in (None, "", "   "):
            with self.assertRaises(QueryException):
                JSONTablePathColumn("a", invalid_type, "$.a")
            with self.assertRaises(QueryException):
                JSONTableExistsColumn("a", invalid_type, "$.a")

    def test_invalid_on_empty_option(self):
        with self.assertRaises(QueryException):
            JSONTablePathColumn("a", "INT", "$.a", on_empty="NULL")

    def test_invalid_on_error_option(self):
        with self.assertRaises(QueryException):
            JSONTablePathColumn("a", "INT", "$.a", on_error="DEFAULT '0'")

    def test_invalid_default(self):
        for invalid_default in (None, "", 123):
            with self.assertRaises(QueryException):
                JSONTableDefault(invalid_default)

    def test_nested_columns_required(self):
        with self.assertRaises(QueryException):
            JSONTableNested("$.b[*]", columns=[])

    def test_unsupported_dialect(self):
        jt = JSONTable(
            '[{"a": 1}]',
            "$[*]",
            columns=[JSONTablePathColumn("a", "INT", "$.a")],
            alias="jt",
        )
        q = PostgreSQLQuery.from_(jt).select(jt.a)

        with self.assertRaises(DialectNotSupported):
            q.get_sql()


class JSONTableImmutabilityTests(unittest.TestCase):
    def test_reusing_node_does_not_modify_it(self):
        jt = JSONTable(
            '[{"a": 1}]',
            "$[*]",
            columns=[JSONTablePathColumn("a", "INT", "$.a")],
            alias="jt",
        )
        q1 = MySQLQuery.from_(jt).select(jt.a)
        sql1 = str(q1)

        q2 = MySQLQuery.from_(jt).select(jt.a).where(jt.a == 1)
        str(q2)

        self.assertEqual(sql1, str(q1))
        self.assertEqual("jt", jt.alias)

    def test_as_does_not_modify_original(self):
        jt = JSONTable(
            '[{"a": 1}]',
            "$[*]",
            columns=[JSONTablePathColumn("a", "INT", "$.a")],
            alias="jt",
        )
        aliased = jt.as_("jt2")

        self.assertEqual("jt", jt.alias)
        self.assertEqual("jt2", aliased.alias)
        self.assertIn("`jt2`", str(MySQLQuery.from_(aliased).select(aliased.a)))
