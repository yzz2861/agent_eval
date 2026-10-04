import unittest
from collections import OrderedDict

from pypika import (
    JSON,
    Array,
    Field,
    JoinException,
    Order,
    QmarkParameter,
    QueryException,
    Table,
)
from pypika.terms import ParameterValueWrapper
from pypika.dialects import PostgreSQLQuery


class InsertTests(unittest.TestCase):
    table_abc = Table("abc")

    def test_array_keyword(self):
        q = PostgreSQLQuery.into(self.table_abc).insert(1, [1, "a", True])

        self.assertEqual("INSERT INTO \"abc\" VALUES (1,ARRAY[1,'a',true])", str(q))


class UpdateTests(unittest.TestCase):
    table_abc = Table("abc")

    def test_postgresquery(self):
        q = PostgreSQLQuery.update(self.table_abc).set(1, [1, "a", True])

        self.assertEqual("UPDATE \"abc\" SET \"1\"=ARRAY[1,'a',true]", str(q))


class JSONObjectTests(unittest.TestCase):
    def test_alias_set_correctly(self):
        table = Table('jsonb_table')
        q = PostgreSQLQuery.from_('abc').select(table.value.get_text_value('a').as_('name'))

        self.assertEqual('''SELECT "value"->>'a' "name" FROM "abc"''', str(q))

    def test_json_value_from_dict(self):
        q = PostgreSQLQuery.select(JSON({"a": "foo"}))

        self.assertEqual('SELECT \'{"a":"foo"}\'', str(q))

    def test_json_value_from_array_num(self):
        q = PostgreSQLQuery.select(JSON([1, 2, 3]))

        self.assertEqual("SELECT '[1,2,3]'", str(q))

    def test_json_value_from_array_str(self):
        q = PostgreSQLQuery.select(JSON(["a", "b", "c"]))

        self.assertEqual('SELECT \'["a","b","c"]\'', str(q))

    def test_json_value_from_dict_recursive(self):
        q = PostgreSQLQuery.select(JSON({"a": "z", "b": {"c": "foo"}, "d": 1}))

        # gotta split this one up to avoid the indeterminate order
        sql = str(q)
        start, end = 9, -2
        self.assertEqual("SELECT '{}'", sql[:start] + sql[end:])

        members_set = set(sql[start:end].split(","))
        self.assertSetEqual({'"a":"z"', '"b":{"c":"foo"}', '"d":1'}, members_set)


class JSONOperatorsTests(unittest.TestCase):
    # reference https://www.postgresql.org/docs/9.5/functions-json.html
    table_abc = Table("abc")

    def test_get_json_value_by_key(self):
        q = PostgreSQLQuery.from_(self.table_abc).select("*").where(self.table_abc.json.get_json_value("dates"))

        self.assertEqual('SELECT * FROM "abc" WHERE "json"->\'dates\'', str(q))

    def test_get_json_value_by_index(self):
        q = PostgreSQLQuery.from_(self.table_abc).select("*").where(self.table_abc.json.get_json_value(1))

        self.assertEqual('SELECT * FROM "abc" WHERE "json"->1', str(q))

    def test_get_text_value_by_key(self):
        q = PostgreSQLQuery.from_(self.table_abc).select("*").where(self.table_abc.json.get_text_value("dates"))

        self.assertEqual('SELECT * FROM "abc" WHERE "json"->>\'dates\'', str(q))

    def test_get_text_value_by_index(self):
        q = PostgreSQLQuery.from_(self.table_abc).select("*").where(self.table_abc.json.get_text_value(1))

        self.assertEqual('SELECT * FROM "abc" WHERE "json"->>1', str(q))

    def test_get_path_json_value(self):
        q = PostgreSQLQuery.from_(self.table_abc).select("*").where(self.table_abc.json.get_path_json_value("{a,b}"))

        self.assertEqual('SELECT * FROM "abc" WHERE "json"#>\'{a,b}\'', str(q))

    def test_get_path_text_value(self):
        q = PostgreSQLQuery.from_(self.table_abc).select("*").where(self.table_abc.json.get_path_text_value("{a,b}"))

        self.assertEqual('SELECT * FROM "abc" WHERE "json"#>>\'{a,b}\'', str(q))


class JSONBOperatorsTests(unittest.TestCase):
    # reference https://www.postgresql.org/docs/9.5/functions-json.html
    table_abc = Table("abc")

    def test_json_contains_for_json(self):
        q = PostgreSQLQuery.select(JSON({"a": 1, "b": 2}).contains({"a": 1}))

        # gotta split this one up to avoid the indeterminate order
        sql = str(q)
        start, end = 9, -13
        self.assertEqual("SELECT '{}'@>'{\"a\":1}'", sql[:start] + sql[end:])

        members_set = set(sql[start:end].split(","))
        self.assertSetEqual({'"a":1', '"b":2'}, members_set)

    def test_json_contains_for_field(self):
        q = (
            PostgreSQLQuery.from_(self.table_abc)
            .select("*")
            .where(self.table_abc.json.contains({"dates": "2018-07-10 - 2018-07-17"}))
        )

        self.assertEqual(
            "SELECT * " 'FROM "abc" ' 'WHERE "json"@>\'{"dates":"2018-07-10 - 2018-07-17"}\'',
            str(q),
        )

    def test_json_contained_by_using_str_arg(self):
        q = (
            PostgreSQLQuery.from_(self.table_abc)
            .select("*")
            .where(
                self.table_abc.json.contained_by(
                    OrderedDict(
                        [
                            ("dates", "2018-07-10 - 2018-07-17"),
                            ("imported", "8"),
                        ]
                    )
                )
            )
        )
        self.assertEqual(
            'SELECT * FROM "abc" ' 'WHERE "json"<@\'{"dates":"2018-07-10 - 2018-07-17","imported":"8"}\'',
            str(q),
        )

    def test_json_contained_by_using_list_arg(self):
        q = (
            PostgreSQLQuery.from_(self.table_abc)
            .select("*")
            .where(self.table_abc.json.contained_by(["One", "Two", "Three"]))
        )

        self.assertEqual('SELECT * FROM "abc" WHERE "json"<@\'["One","Two","Three"]\'', str(q))

    def test_json_contained_by_with_complex_criterion(self):
        q = (
            PostgreSQLQuery.from_(self.table_abc)
            .select("*")
            .where(self.table_abc.json.contained_by(["One", "Two", "Three"]) & (self.table_abc.id == 26))
        )

        self.assertEqual(
            'SELECT * FROM "abc" WHERE "json"<@\'["One","Two","Three"]\' AND "id"=26',
            str(q),
        )

    def test_json_has_key(self):
        q = PostgreSQLQuery.from_(self.table_abc).select("*").where(self.table_abc.json.has_key("dates"))

        self.assertEqual('SELECT * FROM "abc" WHERE "json"?\'dates\'', str(q))

    def test_json_has_keys(self):
        q = PostgreSQLQuery.from_(self.table_abc).select("*").where(self.table_abc.json.has_keys(["dates", "imported"]))

        self.assertEqual("SELECT * FROM \"abc\" WHERE \"json\"?&ARRAY['dates','imported']", str(q))

    def test_json_has_any_keys(self):
        q = (
            PostgreSQLQuery.from_(self.table_abc)
            .select("*")
            .where(self.table_abc.json.has_any_keys(["dates", "imported"]))
        )

        self.assertEqual("SELECT * FROM \"abc\" WHERE \"json\"?|ARRAY['dates','imported']", str(q))

    def test_subnet_contains_inet(self):
        q = (
            PostgreSQLQuery.from_(self.table_abc)
            .select(self.table_abc.a.lshift(2))
            .where(self.table_abc.cidr >> "1.1.1.1")
        )

        self.assertEqual("SELECT \"a\"<<2 FROM \"abc\" WHERE \"cidr\">>'1.1.1.1'", str(q))


class DistinctOnTests(unittest.TestCase):
    table_abc = Table("abc")

    def test_distinct_on(self):
        q = PostgreSQLQuery.from_(self.table_abc).distinct_on("lname", self.table_abc.fname).select("lname", "id")

        self.assertEqual('''SELECT DISTINCT ON("lname","fname") "lname","id" FROM "abc"''', str(q))


class ArrayTests(unittest.TestCase):
    def test_array_syntax(self):
        tb = Table("tb")
        q = PostgreSQLQuery.from_(tb).select(Array(1, "a", ["b", 2, 3]))

        self.assertEqual(str(q), "SELECT ARRAY[1,'a',ARRAY['b',2,3]] FROM \"tb\"")

    def test_render_alias_in_array_sql(self):
        tb = Table("tb")

        q = PostgreSQLQuery.from_(tb).select(Array(tb.col).as_("different_name"))
        self.assertEqual(str(q), 'SELECT ARRAY["col"] "different_name" FROM "tb"')


class ReturningClauseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.table_abc = Table('abc')

    def test_returning_from_missing_table_raises_queryexception(self):
        field_from_diff_table = Field('xyz', table=Table('other'))

        with self.assertRaisesRegex(QueryException, "You can't return from other tables"):
            (
                PostgreSQLQuery.from_(self.table_abc)
                .where(self.table_abc.foo == self.table_abc.bar)
                .delete()
                .returning(field_from_diff_table)
            )

    def test_queryexception_if_returning_used_on_invalid_query(self):
        with self.assertRaisesRegex(QueryException, "Returning can't be used in this query"):
            PostgreSQLQuery.from_(self.table_abc).select('abc').returning('abc')

    def test_no_queryexception_if_returning_used_on_valid_query_type(self):
        # No exceptions for insert, update and delete queries
        with self.subTest('DELETE'):
            PostgreSQLQuery.from_(self.table_abc).where(self.table_abc.foo == self.table_abc.bar).delete().returning(
                "id"
            )
        with self.subTest('UPDATE'):
            PostgreSQLQuery.update(self.table_abc).where(self.table_abc.foo == 0).set("foo", "bar").returning("id")
        with self.subTest('INSERT'):
            PostgreSQLQuery.into(self.table_abc).insert('abc').returning('abc')

    def test_return_field_from_join_table(self):
        new_table = Table('xyz')
        q = (
            PostgreSQLQuery.update(self.table_abc)
            .join(new_table)
            .on(new_table.id == self.table_abc.xyz)
            .where(self.table_abc.foo == 0)
            .set("foo", "bar")
            .returning(new_table.a)
        )

        self.assertEqual(
            'UPDATE "abc" '
            'JOIN "xyz" ON "xyz"."id"="abc"."xyz" '
            'SET "foo"=\'bar\' '
            'WHERE "abc"."foo"=0 '
            'RETURNING "xyz"."a"',
            str(q),
        )


class LateralJoinTests(unittest.TestCase):
    def test_cross_join_lateral(self):
        customers = Table("customers")
        orders = Table("orders")
        latest_order = (
            PostgreSQLQuery.from_(orders)
            .select(orders.total)
            .where(orders.customer_id == customers.id)
            .orderby(orders.created_at, order=Order.desc)
            .limit(1)
            .as_("latest_order")
        )

        query = (
            PostgreSQLQuery.from_(customers).cross_join_lateral(latest_order).select(customers.id, latest_order.total)
        )

        self.assertEqual(
            'SELECT "customers"."id","latest_order"."total" FROM "customers" '
            'CROSS JOIN LATERAL ('
            'SELECT "orders"."total" FROM "orders" '
            'WHERE "orders"."customer_id"="customers"."id" '
            'ORDER BY "orders"."created_at" DESC LIMIT 1) "latest_order"',
            str(query),
        )

    def test_left_join_lateral_keeps_outer_join_semantics(self):
        customers = Table("customers")
        orders = Table("orders")
        latest_order = (
            PostgreSQLQuery.from_(orders)
            .select(orders.total)
            .where(orders.customer_id == customers.id)
            .limit(1)
            .as_("latest_order")
        )

        query = (
            PostgreSQLQuery.from_(customers).left_join_lateral(latest_order).select(customers.id, latest_order.total)
        )
        outer_query = (
            PostgreSQLQuery.from_(customers)
            .left_outer_join_lateral(latest_order)
            .select(customers.id, latest_order.total)
        )

        self.assertIn('LEFT JOIN LATERAL (', str(query))
        self.assertTrue(str(query).endswith(') "latest_order" ON TRUE'))
        self.assertIn('LEFT OUTER JOIN LATERAL (', str(outer_query))
        self.assertTrue(str(outer_query).endswith(') "latest_order" ON TRUE'))

    def test_lateral_can_reference_prior_join_including_self_join(self):
        customers = Table("customers")
        account_managers = customers.as_("account_managers")
        orders = Table("orders")
        latest_order = (
            PostgreSQLQuery.from_(orders)
            .select(orders.total)
            .where(orders.customer_id == customers.id)
            .where(orders.manager_id == account_managers.id)
            .limit(1)
            .as_("latest_order")
        )

        query = (
            PostgreSQLQuery.from_(customers)
            .join(account_managers)
            .on(account_managers.id == customers.manager_id)
            .cross_join_lateral(latest_order)
            .select(customers.id, latest_order.total)
        )

        self.assertIn("\"account_managers\".\"id\"=\"customers\".\"manager_id\"", str(query))
        self.assertIn("CROSS JOIN LATERAL", str(query))

    def test_lateral_cannot_reference_future_relation(self):
        customers = Table("customers")
        orders = Table("orders")
        invoices = Table("invoices")
        latest_order = (
            PostgreSQLQuery.from_(orders)
            .select(orders.total)
            .where(orders.customer_id == customers.id)
            .where(orders.invoice_id == invoices.id)
            .limit(1)
            .as_("latest_order")
        )

        query = (
            PostgreSQLQuery.from_(customers)
            .cross_join_lateral(latest_order)
            .join(invoices)
            .on(invoices.customer_id == customers.id)
            .select(customers.id)
        )

        with self.assertRaisesRegex(JoinException, "introduced to the right of this lateral join"):
            str(query)

    def test_nested_non_lateral_subquery_does_not_inherit_lateral_scope(self):
        customers = Table("customers")
        orders = Table("orders")
        discounts = Table("discounts")
        discount = (
            PostgreSQLQuery.from_(discounts)
            .select(discounts.id, discounts.amount)
            .where(discounts.id == orders.discount_id)
            .as_("discount")
        )
        latest_order = (
            PostgreSQLQuery.from_(orders)
            .join(discount)
            .on(discount.id == orders.discount_id)
            .select(discount.amount)
            .where(orders.customer_id == customers.id)
            .limit(1)
        ).as_("latest_order")

        query = (
            PostgreSQLQuery.from_(customers).cross_join_lateral(latest_order).select(customers.id, latest_order.amount)
        )

        with self.assertRaisesRegex(JoinException, "non-lateral .* cannot see its outer query"):
            str(query)

    def test_same_alias_shadows_outer_relation(self):
        outer_customers = Table("customers")
        local_customers = Table("customers").as_("customers")
        orders = Table("orders")
        latest_order = (
            PostgreSQLQuery.from_(orders)
            .join(local_customers)
            .on(local_customers.id == orders.customer_id)
            .select(orders.total)
            .where(orders.old_customer_id == outer_customers.id)
            .limit(1)
            .as_("latest_order")
        )

        query = PostgreSQLQuery.from_(outer_customers).cross_join_lateral(latest_order).select(outer_customers.id)

        with self.assertRaisesRegex(JoinException, "alias is shadowed"):
            str(query)

    def test_parameters_follow_final_sql_order_and_reuse_does_not_pollute_template(self):
        customers = Table("customers")
        orders = Table("orders")
        latest_order_template = (
            PostgreSQLQuery.from_(orders)
            .select(orders.total)
            .where(orders.customer_id == customers.id)
            .where(orders.is_active == ParameterValueWrapper(QmarkParameter(), True))
            .limit(1)
        )

        latest_order1 = latest_order_template.as_("latest_order")
        latest_order2 = latest_order_template.as_("latest_order")
        query1 = (
            PostgreSQLQuery.from_(customers)
            .cross_join_lateral(latest_order1)
            .select(customers.id, latest_order1.total)
            .where(customers.kind == ParameterValueWrapper(QmarkParameter(), "vip"))
        )
        query2 = (
            PostgreSQLQuery.from_(customers)
            .left_join_lateral(latest_order2)
            .select(customers.id, latest_order2.total)
            .where(customers.kind == ParameterValueWrapper(QmarkParameter(), "regular"))
        )

        parameter1 = QmarkParameter()
        sql1 = query1.get_sql(parameter=parameter1)
        parameter2 = QmarkParameter()
        sql2 = query2.get_sql(parameter=parameter2)

        self.assertEqual([True, "vip"], parameter1.get_parameters())
        self.assertEqual([True, "regular"], parameter2.get_parameters())
        self.assertIsNone(latest_order_template.alias)
        self.assertIn("CROSS JOIN LATERAL", sql1)
        self.assertIn("LEFT JOIN LATERAL", sql2)
