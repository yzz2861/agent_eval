import unittest

from pypika import (
    Field,
    FormatParameter,
    JSONTable,
    JSONTableEmptyOption,
    JSONTableErrorOption,
    JSONTableExistsPathColumn,
    JSONTableNestedPath,
    JSONTableOrdinalityColumn,
    JSONTablePathColumn,
    MySQLQuery,
    OracleQuery,
    PostgreSQLQuery,
    Query,
    RedshiftQuery,
    SQLLiteQuery,
    ClickHouseQuery,
    JiraQuery,
    MSSQLQuery,
    VerticaQuery,
    QueryException,
    Table,
)
from pypika.enums import SqlType, SqlTypeLength, SqlTypes
from pypika.terms import ParameterValueWrapper
from pypika.utils import DialectNotSupported


class MySQLJSONTableTests(unittest.TestCase):
    def test_official_multilevel_nested_path_example(self):
        people = Table("people")
        people_phones = JSONTable(
            people.data,
            "$",
            [
                JSONTablePathColumn("name", "$.name", SqlTypes.VARCHAR(100)),
                JSONTableNestedPath(
                    "$.phones[*]",
                    [
                        JSONTableOrdinalityColumn("phone_ord"),
                        JSONTablePathColumn("phone", "$.phone", SqlTypes.VARCHAR(25)),
                        JSONTableNestedPath(
                            "$.features[*]",
                            [
                                JSONTablePathColumn("feature", "$.feature", SqlTypes.VARCHAR(100)),
                                JSONTablePathColumn("value", "$.value", SqlTypes.VARCHAR(100)),
                            ],
                        ),
                    ],
                ),
            ],
            alias="people_phones",
        )

        query = (
            MySQLQuery.from_(people)
            .join(people_phones)
            .on(people.id == people_phones.person_id)
            .select(
                people_phones.name,
                people_phones.phone,
                people_phones.feature,
                people_phones.value,
            )
        )

        self.assertEqual(
            "SELECT `people_phones`.`name`,`people_phones`.`phone`,`people_phones`.`feature`,`people_phones`.`value` "
            "FROM `people` JOIN JSON_TABLE(`people`.`data`,'$' COLUMNS (`name` VARCHAR(100) PATH '$.name',"
            "NESTED PATH '$.phones[*]' COLUMNS (`phone_ord` FOR ORDINALITY,`phone` VARCHAR(25) PATH '$.phone',"
            "NESTED PATH '$.features[*]' COLUMNS (`feature` VARCHAR(100) PATH '$.feature',"
            "`value` VARCHAR(100) PATH '$.value')))) AS `people_phones` "
            "ON `people`.`id`=`people_phones`.`person_id`",
            str(query),
        )

    def test_columns_can_be_used_in_select_join_and_conditions(self):
        documents = Table("documents")
        items = JSONTable(
            documents.payload,
            "$.items[*]",
            [
                JSONTableOrdinalityColumn("ord"),
                JSONTablePathColumn("id", "$.id", SqlTypes.INTEGER),
                JSONTablePathColumn("name", "$.name", SqlTypes.VARCHAR(50)),
                JSONTableExistsPathColumn("has_note", "$.note"),
            ],
            alias="items",
        )

        query = (
            MySQLQuery.from_(documents)
            .join(items)
            .on(documents.id == Field("document_id", table=items))
            .select(items.ord, items.id, items.name, items.has_note)
            .where(items.name == "key")
        )

        self.assertIn("JOIN JSON_TABLE", str(query))
        self.assertIn("`ord` FOR ORDINALITY", str(query))
        self.assertIn("`id` INTEGER PATH '$.id'", str(query))
        self.assertIn("`has_note` EXISTS PATH '$.note'", str(query))
        self.assertIn("WHERE `items`.`name`='key'", str(query))

    def test_on_empty_on_error_and_json_defaults(self):
        items = JSONTable(
            '[{"name":"O\'Brien"}]',
            "$.items[*]",
            [
                JSONTablePathColumn(
                    "name",
                    "$.name",
                    SqlTypes.VARCHAR(50),
                    default_on_empty={"name": "unknown"},
                    on_empty=JSONTableEmptyOption.default,
                    default_on_error='{"name": "error\'s value"}',
                    on_error=JSONTableErrorOption.default,
                ),
            ],
            alias="items",
        )

        self.assertEqual(
            "SELECT * FROM JSON_TABLE('[{\"name\":\"O''Brien\"}]','$.items[*]' COLUMNS ("
            "`name` VARCHAR(50) PATH '$.name' DEFAULT '{\"name\":\"unknown\"}' ON EMPTY "
            "DEFAULT '{\"name\": \"error''s value\"}' ON ERROR)) AS `items`",
            str(MySQLQuery.from_(items).select("*")),
        )

    def test_parameter_order_only_binds_json_document(self):
        parameter = FormatParameter()
        items = JSONTable(
            ParameterValueWrapper(parameter, "document-value"),
            "$[*]",
            [
                JSONTablePathColumn(
                    "name",
                    "$.name",
                    SqlTypes.VARCHAR(20),
                    default_on_empty="\"missing\"",
                    on_empty=JSONTableEmptyOption.default,
                )
            ],
            alias="items",
        )
        query = MySQLQuery.from_(items).select(items.name).where(items.name == "filter-value")

        sql = query.get_sql(parameter=parameter)

        self.assertEqual(
            "SELECT `items`.`name` FROM JSON_TABLE(%s,'$[*]' COLUMNS (`name` VARCHAR(20) PATH '$.name' "
            "DEFAULT '\"missing\"' ON EMPTY)) AS `items` WHERE `items`.`name`=%s",
            sql,
        )
        self.assertEqual(["document-value", "filter-value"], parameter.get_parameters())

    def test_path_quotes_are_escaped_as_sql_literals(self):
        items = JSONTable(
            "[]",
            "$",
            [
                JSONTablePathColumn("name", '$."O\'Brien"', SqlTypes.VARCHAR(50)),
                JSONTableExistsPathColumn("has_note", '$."note\'s"'),
            ],
            alias="items",
        )

        sql = str(MySQLQuery.from_(items).select(items.name, items.has_note))

        self.assertIn("PATH '$.\"O''Brien\"'", sql)
        self.assertIn("EXISTS PATH '$.\"note''s\"'", sql)

    def test_structured_json_document_is_quoted_and_escaped(self):
        items = JSONTable(
            [{"name": "O'Brien"}],
            "$[*]",
            [JSONTablePathColumn("name", "$.name", SqlTypes.VARCHAR(50))],
            alias="items",
        )

        self.assertIn(
            "JSON_TABLE('[{\"name\":\"O''Brien\"}]'",
            str(MySQLQuery.from_(items).select(items.name)),
        )

    def test_reused_node_is_not_modified(self):
        items = JSONTable(
            "[]",
            "$[*]",
            [JSONTablePathColumn("name", "$.name", SqlTypes.VARCHAR(20))],
            alias="items",
        )
        documents = Table("documents")

        first = str(MySQLQuery.from_(documents).join(items).on(documents.id == items.document_id).select(items.name))
        second = str(MySQLQuery.from_(documents).join(items).on(documents.id == items.document_id).select(items.name))

        self.assertEqual(first, second)
        self.assertEqual("items", items.alias)

    def test_duplicate_output_columns_are_rejected_across_nests(self):
        with self.assertRaisesRegex(QueryException, "Duplicate JSON_TABLE output column: name"):
            JSONTable(
                "[]",
                "$",
                [
                    JSONTablePathColumn("name", "$.name", SqlTypes.VARCHAR(20)),
                    JSONTableNestedPath(
                        "$.items[*]",
                        [JSONTablePathColumn("name", "$.name", SqlTypes.VARCHAR(20))],
                    ),
                ],
                alias="items",
            )

    def test_path_column_requires_type(self):
        with self.assertRaisesRegex(QueryException, "requires a SQL data type"):
            JSONTablePathColumn("name", "$.name", 20)

        with self.assertRaisesRegex(QueryException, "Unsupported JSON_TABLE column data type"):
            JSONTablePathColumn("name", "$.name", "VARCHAR(20)")

        with self.assertRaisesRegex(QueryException, "Unsupported JSON_TABLE column data type"):
            JSONTablePathColumn("name", "$.name", SqlType("VARCHAR(20); DROP TABLE people"))

        with self.assertRaisesRegex(QueryException, "length must be a non-negative integer"):
            JSONTablePathColumn("name", "$.name", SqlTypeLength("VARCHAR", -1))

    def test_raw_string_column_definition_is_rejected(self):
        with self.assertRaisesRegex(QueryException, "structured column definitions"):
            JSONTable("[]", "$", ["name VARCHAR(20) PATH '$.name'"], alias="items")

    def test_alias_is_required(self):
        items = JSONTable("[]", "$", [JSONTablePathColumn("name", "$.name", SqlTypes.VARCHAR(20))])
        with self.assertRaisesRegex(QueryException, "requires an alias"):
            str(MySQLQuery.from_(items).select("*"))

    def test_invalid_path_and_options_are_rejected(self):
        with self.assertRaisesRegex(QueryException, "start with '\$'"):
            JSONTablePathColumn("name", "name", SqlTypes.VARCHAR(20))

        with self.assertRaisesRegex(QueryException, "DEFAULT ON EMPTY requires"):
            JSONTablePathColumn("name", "$.name", SqlTypes.VARCHAR(20), on_empty=JSONTableEmptyOption.default)

        with self.assertRaisesRegex(QueryException, "Invalid JSON default"):
            JSONTablePathColumn(
                "name",
                "$.name",
                SqlTypes.VARCHAR(20),
                on_empty=JSONTableEmptyOption.default,
                default_on_empty="not-json",
            )

        with self.assertRaisesRegex(QueryException, "Invalid JSON document"):
            JSONTable(
                "not-json",
                "$",
                [JSONTablePathColumn("name", "$.name", SqlTypes.VARCHAR(20))],
                alias="items",
            )

    def test_other_dialects_are_unsupported(self):
        items = JSONTable("[]", "$", [JSONTablePathColumn("name", "$.name", SqlTypes.VARCHAR(20))], alias="items")
        for query_cls in (
            Query,
            ClickHouseQuery,
            JiraQuery,
            MSSQLQuery,
            OracleQuery,
            PostgreSQLQuery,
            RedshiftQuery,
            SQLLiteQuery,
            VerticaQuery,
        ):
            with self.subTest(query_cls=query_cls.__name__):
                with self.assertRaisesRegex(DialectNotSupported, "only supported by MySQL"):
                    str(query_cls.from_(items).select("*"))


if __name__ == "__main__":
    unittest.main()
