import unittest

from pypika import AliasedQuery, Query, RelationRewriteException, Table, functions as fn


class RelationRewriteTests(unittest.TestCase):
    def test_three_level_correlated_query_and_self_join(self):
        orders = Table("orders")
        parent_orders = Table("orders", alias="parent_orders")
        cte_orders = Table("orders")
        notes = Table("order_notes")
        events = Table("events")

        closed_orders = Query.from_(cte_orders).select(cte_orders.id).where(cte_orders.status == "closed")
        note_count = (
            Query.from_(notes)
            .select(fn.Count("*"))
            .where(notes.order_id == orders.id)
            .where(
                notes.note_date
                >= Query.from_(events).select(fn.Max(events.created_at)).where(events.order_id == orders.id)
            )
        )
        query = (
            Query.with_(closed_orders, "closed_orders")
            .from_(orders)
            .join(parent_orders)
            .on(orders.parent_id == parent_orders.id)
            .select(orders.id, parent_orders.id.as_("parent_id"), note_count.as_("note_count"))
            .where(orders.status == "active")
            .groupby(orders.id, parent_orders.id)
            .having(fn.Count("*") > 0)
            .orderby(orders.id)
        )

        original_sql = str(query)
        archived = Query.from_(Table("orders_archive")).select("id", "parent_id", "status").as_("orders")

        rewritten = query.replace_relation(orders, archived)

        self.assertEqual(
            "WITH closed_orders AS (SELECT \"id\" FROM \"orders\" WHERE \"status\"='closed') "
            "SELECT \"orders\".\"id\",\"parent_orders\".\"id\" \"parent_id\","
            "(SELECT COUNT(*) FROM \"order_notes\" "
            "WHERE \"order_notes\".\"order_id\"=\"orders\".\"id\" "
            "AND \"order_notes\".\"note_date\">=(SELECT MAX(\"events\".\"created_at\") "
            "FROM \"events\" WHERE \"events\".\"order_id\"=\"orders\".\"id\")) \"note_count\" "
            "FROM \"orders\" JOIN \"orders\" \"parent_orders\" "
            "ON \"orders\".\"parent_id\"=\"parent_orders\".\"id\" "
            "WHERE \"orders\".\"status\"='active' "
            "GROUP BY \"orders\".\"id\",\"parent_orders\".\"id\" HAVING COUNT(*)>0 "
            "ORDER BY \"orders\".\"id\"",
            original_sql,
        )
        self.assertEqual(
            original_sql.replace(
                'FROM "orders" JOIN', 'FROM (SELECT "id","parent_id","status" FROM "orders_archive") "orders" JOIN'
            ),
            str(rewritten),
        )
        self.assertEqual(original_sql, str(query))

    def test_inner_rebound_same_name_is_untouched(self):
        outer = Table("orders")
        inner = Table("orders")
        events = Table("events")
        correlated = Query.from_(events).select(fn.Count("*")).where(events.order_id == outer.id)
        local = Query.from_(inner).select(inner.id)
        query = Query.from_(outer).select(outer.id, correlated.as_("event_count"), local.as_("local"))

        archived = Query.from_(Table("orders_archive")).select("id").as_("orders")
        rewritten = query.replace_relation(outer, archived)

        self.assertIn('FROM "orders") "local"', str(rewritten))
        self.assertIn('FROM (SELECT "id" FROM "orders_archive") "orders"', str(rewritten))
        self.assertEqual(str(query), str(query))

    def test_inner_relation_shadowing_outer_reference_is_ambiguous(self):
        outer = Table("orders")
        inner = Table("orders")
        events = Table("events")
        shadowed = Query.from_(inner).select(inner.id).where(inner.id == outer.id)
        query = Query.from_(outer).select(outer.id, events.id).join(events).on(events.order_id == outer.id)
        query = query.where(outer.id.isin(shadowed))
        archived = Query.from_(Table("orders_archive")).select("id").as_("orders")

        with self.assertRaisesRegex(RelationRewriteException, "shadowed"):
            query.replace_relation(outer, archived)

    def test_target_inside_cte_is_rewritten(self):
        orders = Table("orders")
        closed_orders = Query.from_(orders).select(orders.id)
        query = Query.with_(closed_orders, "closed_orders").from_(AliasedQuery("closed_orders")).select("id")

        rewritten = query.replace_relation(orders, Table("orders_archive"))

        self.assertIn('WITH closed_orders AS (SELECT "id" FROM "orders_archive")', str(rewritten))

    def test_replacement_subquery_must_have_required_columns(self):
        orders = Table("orders")
        query = Query.from_(orders).select(orders.id, orders.status)
        archived = Query.from_(Table("orders_archive")).select("id").as_("orders")

        with self.assertRaisesRegex(RelationRewriteException, "status"):
            query.replace_relation(orders, archived)

    def test_replacement_subquery_must_be_aliased(self):
        orders = Table("orders")
        query = Query.from_(orders).select(orders.id)
        archived = Query.from_(Table("orders_archive")).select("id")

        with self.assertRaisesRegex(RelationRewriteException, "alias"):
            query.replace_relation(orders, archived)

    def test_join_using_columns_are_compatibility_checked(self):
        orders = Table("orders")
        customers = Table("customers")
        query = Query.from_(orders).join(customers).using("customer_id").select(orders.id)
        archived = Query.from_(Table("orders_archive")).select("id").as_("orders")

        with self.assertRaisesRegex(RelationRewriteException, "customer_id"):
            query.replace_relation(orders, archived)

    def test_target_must_be_bound_exactly_once(self):
        orders = Table("orders")
        query = Query.from_(orders).select(orders.id)
        unrelated = Table("orders")
        archived = Table("orders_archive")

        with self.assertRaisesRegex(RelationRewriteException, "exactly one binding"):
            query.replace_relation(unrelated, archived)

    def test_same_relation_object_used_twice_is_ambiguous(self):
        orders = Table("orders", alias="o1")
        query = Query.from_(orders).join(orders).on(orders.id == orders.parent_id).select(orders.id)
        archived = Table("orders_archive", alias="o1")

        with self.assertRaisesRegex(RelationRewriteException, "more than once"):
            query.replace_relation(orders, archived)


if __name__ == "__main__":
    unittest.main()
