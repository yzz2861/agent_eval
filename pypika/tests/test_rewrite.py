import unittest

from pypika import AliasedQuery, Field, Query, Table
from pypika import functions as fn
from pypika.rewrite import (
    AmbiguousRelationError,
    IncompatibleColumnsError,
    RelationNotFoundError,
    UnboundRelationError,
    find_relation,
    iter_relations,
    replace_relation,
)
from pypika.terms import ExistsCriterion


class SelfJoinTests(unittest.TestCase):
    def setUp(self):
        self.o1 = Table("orders").as_("o1")
        self.o2 = Table("orders").as_("o2")
        self.query = (
            Query.from_(self.o1)
            .join(self.o2)
            .on(self.o1.parent_id == self.o2.id)
            .select(self.o1.id, self.o2.id)
            .where(self.o2.status == "shipped")
            .orderby(self.o1.id)
        )
        self.expected_before = (
            "SELECT \"o1\".\"id\",\"o2\".\"id\" FROM \"orders\" \"o1\" JOIN \"orders\" \"o2\" "
            "ON \"o1\".\"parent_id\"=\"o2\".\"id\" WHERE \"o2\".\"status\"='shipped' ORDER BY \"o1\".\"id\""
        )

    def test_replace_from_side_of_self_join(self):
        rewritten = replace_relation(self.query, self.o1, Table("orders_archive"))

        self.assertEqual(
            "SELECT \"o1\".\"id\",\"o2\".\"id\" FROM \"orders_archive\" \"o1\" JOIN \"orders\" \"o2\" "
            "ON \"o1\".\"parent_id\"=\"o2\".\"id\" WHERE \"o2\".\"status\"='shipped' ORDER BY \"o1\".\"id\"",
            str(rewritten),
        )

    def test_replace_join_side_of_self_join(self):
        rewritten = replace_relation(self.query, self.o2, Table("orders_archive"))

        self.assertEqual(
            "SELECT \"o1\".\"id\",\"o2\".\"id\" FROM \"orders\" \"o1\" JOIN \"orders_archive\" \"o2\" "
            "ON \"o1\".\"parent_id\"=\"o2\".\"id\" WHERE \"o2\".\"status\"='shipped' ORDER BY \"o1\".\"id\"",
            str(rewritten),
        )

    def test_replacement_alias_is_inherited_when_missing(self):
        rewritten = replace_relation(self.query, self.o1, "orders_archive")

        self.assertIn("FROM \"orders_archive\" \"o1\"", str(rewritten))

    def test_explicit_replacement_alias_rewrites_field_namespaces(self):
        rewritten = replace_relation(self.query, self.o1, Table("orders_archive").as_("oa"))

        self.assertEqual(
            "SELECT \"oa\".\"id\",\"o2\".\"id\" FROM \"orders_archive\" \"oa\" JOIN \"orders\" \"o2\" "
            "ON \"oa\".\"parent_id\"=\"o2\".\"id\" WHERE \"o2\".\"status\"='shipped' ORDER BY \"oa\".\"id\"",
            str(rewritten),
        )

    def test_original_query_is_not_mutated(self):
        replace_relation(self.query, self.o1, Table("orders_archive"))

        self.assertEqual(self.expected_before, str(self.query))
        self.assertIs(self.query._from[0], self.o1)


class CorrelatedSubqueryTests(unittest.TestCase):
    """
    Three nesting levels: the target relation is referenced from a WHERE subquery and, one
    level deeper, from a scalar subquery.  A second subquery re-binds the same table name and
    alias and must not be touched.
    """

    def setUp(self):
        self.o = Table("orders").as_("o")
        self.i = Table("order_items").as_("i")
        self.p = Table("payments").as_("p")
        self.o_shadow = Table("orders").as_("o")  # same name and alias, different binding

        level3 = Query.from_(self.p).select(fn.Avg(self.p.amount)).where(self.p.order_id == self.o.id)
        level2 = Query.from_(self.i).select(self.i.id).where(self.i.order_id == self.o.id).where(self.i.price > level3)
        shadow = Query.from_(self.o_shadow).select(self.o_shadow.id).where(self.o_shadow.status == "X")
        self.query = (
            Query.from_(self.o)
            .select(self.o.id, self.o.total)
            .where(self.o.status == "A")
            .where(ExistsCriterion(level2))
            .where(ExistsCriterion(shadow))
            .groupby(self.o.id, self.o.total)
            .having(fn.Count(self.o.id) > 1)
            .orderby(self.o.total)
        )
        self.expected_before = (
            "SELECT \"o\".\"id\",\"o\".\"total\" FROM \"orders\" \"o\" "
            "WHERE \"o\".\"status\"='A' "
            "AND EXISTS (SELECT \"i\".\"id\" FROM \"order_items\" \"i\" "
            "WHERE \"i\".\"order_id\"=\"o\".\"id\" AND \"i\".\"price\">"
            "(SELECT AVG(\"p\".\"amount\") FROM \"payments\" \"p\" WHERE \"p\".\"order_id\"=\"o\".\"id\")) "
            "AND EXISTS (SELECT \"o\".\"id\" FROM \"orders\" \"o\" WHERE \"o\".\"status\"='X') "
            "GROUP BY \"o\".\"id\",\"o\".\"total\" HAVING COUNT(\"o\".\"id\")>1 ORDER BY \"o\".\"total\""
        )

    def test_replace_with_aliased_subquery(self):
        archive = Query.from_(Table("orders_archive")).select("id", "total", "status", "parent_id").as_("oa")
        rewritten = replace_relation(self.query, self.o, archive)

        self.assertEqual(
            "SELECT \"oa\".\"id\",\"oa\".\"total\" "
            "FROM (SELECT \"id\",\"total\",\"status\",\"parent_id\" FROM \"orders_archive\") \"oa\" "
            "WHERE \"oa\".\"status\"='A' "
            "AND EXISTS (SELECT \"i\".\"id\" FROM \"order_items\" \"i\" "
            "WHERE \"i\".\"order_id\"=\"oa\".\"id\" AND \"i\".\"price\">"
            "(SELECT AVG(\"p\".\"amount\") FROM \"payments\" \"p\" WHERE \"p\".\"order_id\"=\"oa\".\"id\")) "
            "AND EXISTS (SELECT \"o\".\"id\" FROM \"orders\" \"o\" WHERE \"o\".\"status\"='X') "
            "GROUP BY \"oa\".\"id\",\"oa\".\"total\" HAVING COUNT(\"oa\".\"id\")>1 ORDER BY \"oa\".\"total\"",
            str(rewritten),
        )

    def test_shadowed_relation_with_same_name_and_alias_is_untouched(self):
        rewritten = replace_relation(self.query, self.o, Table("orders_archive"))

        self.assertIn("EXISTS (SELECT \"o\".\"id\" FROM \"orders\" \"o\" WHERE \"o\".\"status\"='X')", str(rewritten))
        self.assertEqual(1, str(rewritten).count("FROM \"orders\" \"o\""))

    def test_original_query_is_not_mutated(self):
        replace_relation(self.query, self.o, Table("orders_archive"))

        self.assertEqual(self.expected_before, str(self.query))

    def test_untouched_subtrees_are_shared_not_copied(self):
        rewritten = replace_relation(self.query, self.o, Table("orders_archive"))

        # the shadowing EXISTS branch contains no reference to the target and is reused as-is
        self.assertIs(self.query._wheres.right, rewritten._wheres.right)


class CTETests(unittest.TestCase):
    def test_relation_inside_cte_body_is_replaced(self):
        o = Table("orders").as_("o")
        body = Query.from_(o).select(o.id, o.total).where(o.status == "recent")
        query = Query.with_(body, "recent_orders").from_(AliasedQuery("recent_orders")).select("*")

        expected_before = (
            "WITH recent_orders AS (SELECT \"o\".\"id\",\"o\".\"total\" FROM \"orders\" \"o\" "
            "WHERE \"o\".\"status\"='recent') SELECT * FROM recent_orders"
        )
        self.assertEqual(expected_before, str(query))

        rewritten = replace_relation(query, o, "orders_archive")

        self.assertEqual(
            "WITH recent_orders AS (SELECT \"o\".\"id\",\"o\".\"total\" FROM \"orders_archive\" \"o\" "
            "WHERE \"o\".\"status\"='recent') SELECT * FROM recent_orders",
            str(rewritten),
        )
        # the CTE reference in the outer query is untouched, and so is the original query
        self.assertIsInstance(rewritten._from[0], AliasedQuery)
        self.assertEqual(expected_before, str(query))


class StarTests(unittest.TestCase):
    def test_star_of_target_relation_is_repointed(self):
        t = Table("orders").as_("t")
        query = Query.from_(t).select(t.star)

        rewritten = replace_relation(query, t, Table("orders_archive").as_("ta"))

        self.assertEqual("SELECT \"ta\".* FROM \"orders_archive\" \"ta\"", str(rewritten))
        self.assertEqual("SELECT \"t\".* FROM \"orders\" \"t\"", str(query))


class SubqueryReplacementTests(unittest.TestCase):
    def setUp(self):
        self.o = Table("orders").as_("o")
        self.query = Query.from_(self.o).select(self.o.id, self.o.total)

    def test_compatible_subquery_replacement(self):
        archive = Query.from_(Table("orders_archive")).select("id", "total").as_("oa")

        rewritten = replace_relation(self.query, self.o, archive)

        self.assertEqual(
            "SELECT \"oa\".\"id\",\"oa\".\"total\" FROM (SELECT \"id\",\"total\" FROM \"orders_archive\") \"oa\"",
            str(rewritten),
        )

    def test_incompatible_subquery_replacement_raises(self):
        archive = Query.from_(Table("orders_archive")).select("id").as_("oa")

        with self.assertRaises(IncompatibleColumnsError):
            replace_relation(self.query, self.o, archive)

    def test_unaliased_subquery_replacement_inherits_alias(self):
        archive = Query.from_(Table("orders_archive")).select("id", "total")

        rewritten = replace_relation(self.query, self.o, archive)

        self.assertIn("FROM (SELECT \"id\",\"total\" FROM \"orders_archive\") \"o\"", str(rewritten))
        self.assertIsNone(archive.alias)

    def test_replacement_argument_is_not_mutated(self):
        archive_table = Table("orders_archive")

        replace_relation(self.query, self.o, archive_table)

        self.assertIsNone(archive_table.alias)


class ResolutionErrorTests(unittest.TestCase):
    def test_unknown_target_raises(self):
        query = Query.from_(Table("orders")).select("id")

        with self.assertRaises(RelationNotFoundError):
            replace_relation(query, Table("customers"), "orders_archive")

    def test_ambiguous_field_reference_raises(self):
        o1 = Table("orders").as_("o")
        o2 = Table("order_items").as_("o")  # colliding alias in the same scope
        query = Query.from_(o1).join(o2).on(o1.id == o2.order_id).select(o1.id)
        query = query.where(Field("id", table=Table("anything").as_("o")) == 1)

        with self.assertRaises(AmbiguousRelationError):
            replace_relation(query, o1, "orders_archive")

    def test_unbound_reference_to_target_namespace_raises(self):
        o = Table("orders").as_("o")
        # a derived table is a non-correlated scope: the outer alias is not visible inside
        derived = Query.from_(Table("x").as_("x")).select(Field("id", table=Table("orders").as_("o"))).as_("d")
        query = Query.from_(o).join(derived).on(o.id == derived.id).select(o.id)

        with self.assertRaises(UnboundRelationError):
            replace_relation(query, o, "orders_archive")

    def test_same_instance_in_two_scopes_requires_disambiguation(self):
        shared = Table("orders").as_("s")
        query = Query.from_(shared).select(shared.id).union(Query.from_(shared).select(shared.id))

        with self.assertRaises(AmbiguousRelationError):
            find_relation(query, shared)

        refs = iter_relations(query)
        self.assertEqual(2, len(refs))

        rewritten = replace_relation(query, refs[0], "orders_archive")

        self.assertEqual(
            "(SELECT \"s\".\"id\" FROM \"orders_archive\" \"s\") UNION (SELECT \"s\".\"id\" FROM \"orders\" \"s\")",
            str(rewritten),
        )


class FindRelationTests(unittest.TestCase):
    def setUp(self):
        self.o = Table("orders").as_("o")
        self.i = Table("order_items").as_("i")
        sub = Query.from_(self.i).select(self.i.id).where(self.i.order_id == self.o.id)
        self.query = Query.from_(self.o).select(self.o.id).where(ExistsCriterion(sub))

    def test_iter_relations_covers_all_scopes(self):
        refs = iter_relations(self.query)

        self.assertEqual(2, len(refs))
        self.assertEqual({"o", "i"}, {ref.name for ref in refs})
        self.assertEqual({"from"}, {ref.kind for ref in refs})

    def test_find_relation_by_alias(self):
        ref = find_relation(self.query, "i")

        self.assertIs(ref.selectable, self.i)

    def test_find_relation_by_table_name(self):
        ref = find_relation(self.query, "order_items")

        self.assertIs(ref.selectable, self.i)

    def test_find_relation_by_predicate(self):
        ref = find_relation(self.query, lambda r: r.kind == "from" and r.index == 0 and r.name == "i")

        self.assertIs(ref.selectable, self.i)

    def test_find_relation_ambiguous_match_raises(self):
        with self.assertRaises(AmbiguousRelationError):
            find_relation(self.query, lambda r: True)

    def test_replace_accepts_relation_ref(self):
        ref = find_relation(self.query, "i")

        rewritten = replace_relation(self.query, ref, "order_items_archive")

        self.assertEqual(
            "SELECT \"o\".\"id\" FROM \"orders\" \"o\" "
            "WHERE EXISTS (SELECT \"i\".\"id\" FROM \"order_items_archive\" \"i\" "
            "WHERE \"i\".\"order_id\"=\"o\".\"id\")",
            str(rewritten),
        )
