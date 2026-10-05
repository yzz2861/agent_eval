import unittest

from pypika import Field, MergeException, Parameter, Query, Table
from pypika.dialects import MSSQLQuery, PostgreSQLQuery
from pypika.merge import MergeWhenClause


class PostgreSQLMergeTests(unittest.TestCase):
    target = Table("inventory", alias="t")
    source = Table("staging", alias="s")

    def test_merge_with_all_clause_types(self):
        q = (
            PostgreSQLQuery.merge_into(self.target)
            .using(self.source)
            .on(self.target.sku == self.source.sku)
            .when_matched_then_update({self.target.qty: self.source.qty}, condition=self.source.qty > 0)
            .when_matched_then_delete()
            .when_not_matched_then_insert(columns=["sku", "qty"], values=[self.source.sku, self.source.qty])
        )

        self.assertEqual(
            'MERGE INTO "inventory" "t" USING "staging" "s" ON "t"."sku"="s"."sku" '
            'WHEN MATCHED AND "s"."qty">0 THEN UPDATE SET "qty"="s"."qty" '
            'WHEN MATCHED THEN DELETE '
            'WHEN NOT MATCHED THEN INSERT ("sku", "qty") VALUES ("s"."sku", "s"."qty")',
            str(q),
        )

    def test_merge_with_string_table_names_and_constant_updates(self):
        target = Table("inventory")
        source = Table("staging")
        q = (
            PostgreSQLQuery.merge_into(target)
            .using(source)
            .on(target.sku == source.sku)
            .when_matched_then_update(qty=0, note="archived")
        )

        self.assertEqual(
            'MERGE INTO "inventory" USING "staging" ON "inventory"."sku"="staging"."sku" '
            "WHEN MATCHED THEN UPDATE SET \"qty\"=0, \"note\"='archived'",
            str(q),
        )

    def test_merge_insert_without_column_list(self):
        q = (
            PostgreSQLQuery.merge_into(self.target)
            .using(self.source)
            .on(self.target.sku == self.source.sku)
            .when_not_matched_then_insert(values=[self.source.sku, self.source.qty])
        )

        self.assertEqual(
            'MERGE INTO "inventory" "t" USING "staging" "s" ON "t"."sku"="s"."sku" '
            'WHEN NOT MATCHED THEN INSERT VALUES ("s"."sku", "s"."qty")',
            str(q),
        )

    def test_merge_with_subquery_source(self):
        staging = Table("staging")
        subquery = PostgreSQLQuery.from_(staging).select(staging.sku, staging.qty).where(staging.qty > 10).as_("src")
        q = (
            PostgreSQLQuery.merge_into(self.target)
            .using(subquery)
            .on(self.target.sku == subquery.sku)
            .when_not_matched_then_insert(columns=["sku", "qty"], values=[subquery.sku, subquery.qty])
        )

        self.assertEqual(
            'MERGE INTO "inventory" "t" '
            'USING (SELECT "sku","qty" FROM "staging" WHERE "qty">10) "src" '
            'ON "t"."sku"="src"."sku" '
            'WHEN NOT MATCHED THEN INSERT ("sku", "qty") VALUES ("src"."sku", "src"."qty")',
            str(q),
        )

    def test_merge_with_parameters(self):
        q = (
            PostgreSQLQuery.merge_into(self.target)
            .using(self.source)
            .on(self.target.sku == self.source.sku)
            .when_matched_then_update({"qty": Parameter("%s")}, condition=self.source.qty > Parameter("%s"))
            .when_not_matched_then_insert(columns=["sku", "qty"], values=[Parameter("%s"), 0])
        )

        self.assertEqual(
            'MERGE INTO "inventory" "t" USING "staging" "s" ON "t"."sku"="s"."sku" '
            'WHEN MATCHED AND "s"."qty">%s THEN UPDATE SET "qty"=%s '
            'WHEN NOT MATCHED THEN INSERT ("sku", "qty") VALUES (%s, 0)',
            str(q),
        )

    def test_merge_with_multiple_on_conditions(self):
        q = (
            PostgreSQLQuery.merge_into(self.target)
            .using(self.source)
            .on(self.target.sku == self.source.sku)
            .on(self.target.warehouse == self.source.warehouse)
            .when_matched_then_delete()
        )

        self.assertEqual(
            'MERGE INTO "inventory" "t" USING "staging" "s" '
            'ON "t"."sku"="s"."sku" AND "t"."warehouse"="s"."warehouse" '
            'WHEN MATCHED THEN DELETE',
            str(q),
        )

    def test_merge_with_generic_query_class(self):
        target = Table("inventory")
        source = Table("staging")
        q = Query.merge_into(target).using(source).on(target.sku == source.sku).when_matched_then_delete()

        self.assertEqual(
            'MERGE INTO "inventory" USING "staging" ON "inventory"."sku"="staging"."sku" ' 'WHEN MATCHED THEN DELETE',
            str(q),
        )

    def test_merge_is_immutable(self):
        base = PostgreSQLQuery.merge_into(self.target).using(self.source).on(self.target.sku == self.source.sku)

        q1 = base.when_matched_then_delete()
        q2 = base.when_matched_then_update({"qty": 1})

        self.assertIn("DELETE", str(q1))
        self.assertNotIn("UPDATE", str(q1))
        self.assertIn("UPDATE", str(q2))
        self.assertNotIn("DELETE", str(q2))


class MSSQLMergeTests(unittest.TestCase):
    target = Table("inventory", alias="t")
    source = Table("staging", alias="s")

    def test_merge_with_all_clause_types(self):
        q = (
            MSSQLQuery.merge_into(self.target)
            .using(self.source)
            .on(self.target.sku == self.source.sku)
            .when_matched_then_update({"qty": self.source.qty}, condition=self.source.qty > 0)
            .when_matched_then_delete()
            .when_not_matched_then_insert(columns=["sku", "qty"], values=[self.source.sku, self.source.qty])
            .when_not_matched_by_source_then_update({"qty": 0}, condition=self.target.qty < 0)
            .when_not_matched_by_source_then_delete()
        )

        self.assertEqual(
            'MERGE INTO "inventory" "t" USING "staging" "s" ON "t"."sku"="s"."sku" '
            'WHEN MATCHED AND "s"."qty">0 THEN UPDATE SET "qty"="s"."qty" '
            'WHEN MATCHED THEN DELETE '
            'WHEN NOT MATCHED THEN INSERT ("sku", "qty") VALUES ("s"."sku", "s"."qty") '
            'WHEN NOT MATCHED BY SOURCE AND "t"."qty"<0 THEN UPDATE SET "qty"=0 '
            'WHEN NOT MATCHED BY SOURCE THEN DELETE;',
            str(q),
        )

    def test_merge_is_terminated_with_semicolon(self):
        q = (
            MSSQLQuery.merge_into(self.target)
            .using(self.source)
            .on(self.target.sku == self.source.sku)
            .when_matched_then_delete()
        )

        self.assertTrue(str(q).endswith(";"))

    def test_merge_with_subquery_source(self):
        staging = Table("staging")
        subquery = MSSQLQuery.from_(staging).select(staging.sku, staging.qty).as_("src")
        q = (
            MSSQLQuery.merge_into(self.target)
            .using(subquery)
            .on(self.target.sku == subquery.sku)
            .when_not_matched_then_insert(columns=["sku", "qty"], values=[subquery.sku, subquery.qty])
        )

        self.assertEqual(
            'MERGE INTO "inventory" "t" USING (SELECT "sku","qty" FROM "staging") "src" '
            'ON "t"."sku"="src"."sku" '
            'WHEN NOT MATCHED THEN INSERT ("sku", "qty") VALUES ("src"."sku", "src"."qty");',
            str(q),
        )


class MergeValidationTests(unittest.TestCase):
    target = Table("inventory", alias="t")
    source = Table("staging", alias="s")

    def merge(self, query_cls=PostgreSQLQuery):
        return query_cls.merge_into(self.target).using(self.source).on(self.target.sku == self.source.sku)

    def test_unconditional_matched_clause_makes_following_clauses_unreachable(self):
        with self.assertRaises(MergeException):
            self.merge().when_matched_then_delete().when_matched_then_update({"qty": 1}, condition=self.source.qty > 0)

    def test_unconditional_not_matched_clause_makes_following_clauses_unreachable(self):
        with self.assertRaises(MergeException):
            self.merge().when_not_matched_then_insert(values=[1, 2]).when_not_matched_then_insert(
                values=[1, 2], condition=self.source.qty > 0
            )

    def test_unconditional_not_matched_by_source_clause_makes_following_clauses_unreachable(self):
        with self.assertRaises(MergeException):
            self.merge(MSSQLQuery).when_not_matched_by_source_then_delete().when_not_matched_by_source_then_update(
                {"qty": 0}, condition=self.target.qty < 0
            )

    def test_postgresql_does_not_support_not_matched_by_source(self):
        with self.assertRaises(MergeException):
            self.merge().when_not_matched_by_source_then_delete()
        with self.assertRaises(MergeException):
            self.merge().when_not_matched_by_source_then_update({"qty": 0})

    def test_mssql_allows_at_most_two_matched_clauses(self):
        with self.assertRaises(MergeException):
            (
                self.merge(MSSQLQuery)
                .when_matched_then_update({"qty": 1}, condition=self.source.qty > 0)
                .when_matched_then_delete(condition=self.source.qty < 0)
                .when_matched_then_delete()
            )

    def test_mssql_disallows_two_updates_in_matched_clauses(self):
        with self.assertRaises(MergeException):
            (
                self.merge(MSSQLQuery)
                .when_matched_then_update({"qty": 1}, condition=self.source.qty > 0)
                .when_matched_then_update({"qty": 2})
            )

    def test_mssql_allows_at_most_one_not_matched_clause(self):
        with self.assertRaises(MergeException):
            (
                self.merge(MSSQLQuery)
                .when_not_matched_then_insert(values=[1, 2], condition=self.source.qty > 0)
                .when_not_matched_then_insert(values=[1, 2])
            )

    def test_mssql_disallows_two_deletes_in_not_matched_by_source_clauses(self):
        with self.assertRaises(MergeException):
            (
                self.merge(MSSQLQuery)
                .when_not_matched_by_source_then_delete(condition=self.target.qty < 0)
                .when_not_matched_by_source_then_delete()
            )

    def test_duplicate_update_column_is_rejected(self):
        with self.assertRaises(MergeException):
            self.merge().when_matched_then_update([("qty", 1), (self.target.qty, 2)])

    def test_duplicate_insert_column_is_rejected(self):
        with self.assertRaises(MergeException):
            self.merge().when_not_matched_then_insert(columns=["sku", "sku"], values=[1, 2])

    def test_raw_sql_condition_is_rejected(self):
        with self.assertRaises(MergeException):
            (PostgreSQLQuery.merge_into(self.target).using(self.source).on('"t"."sku" = "s"."sku"'))

    def test_raw_sql_clause_condition_is_rejected(self):
        with self.assertRaises(MergeException):
            self.merge().when_matched_then_delete(condition="qty > 0")

    def test_update_column_from_source_table_is_rejected(self):
        with self.assertRaises(MergeException):
            self.merge().when_matched_then_update({self.source.qty: 1})

    def test_insert_column_from_source_table_is_rejected(self):
        with self.assertRaises(MergeException):
            self.merge().when_not_matched_then_insert(columns=[self.source.sku], values=[1])

    def test_insert_column_value_count_mismatch_is_rejected(self):
        with self.assertRaises(MergeException):
            self.merge().when_not_matched_then_insert(columns=["sku", "qty"], values=[1])

    def test_empty_update_is_rejected(self):
        with self.assertRaises(MergeException):
            self.merge().when_matched_then_update()

    def test_empty_insert_is_rejected(self):
        with self.assertRaises(MergeException):
            self.merge().when_not_matched_then_insert(values=[])

    def test_subquery_source_without_alias_is_rejected(self):
        staging = Table("staging")
        subquery = PostgreSQLQuery.from_(staging).select(staging.sku)
        with self.assertRaises(MergeException):
            PostgreSQLQuery.merge_into(self.target).using(subquery)

    def test_invalid_source_type_is_rejected(self):
        with self.assertRaises(MergeException):
            PostgreSQLQuery.merge_into(self.target).using(123)

    def test_illegal_action_combination_is_rejected(self):
        with self.assertRaises(MergeException):
            MergeWhenClause(MergeWhenClause.MATCHED, MergeWhenClause.INSERT)
        with self.assertRaises(MergeException):
            MergeWhenClause(MergeWhenClause.NOT_MATCHED, MergeWhenClause.UPDATE)
        with self.assertRaises(MergeException):
            MergeWhenClause(MergeWhenClause.NOT_MATCHED_BY_SOURCE, MergeWhenClause.INSERT)

    def test_when_clause_requires_on_condition_first(self):
        with self.assertRaises(MergeException):
            PostgreSQLQuery.merge_into(self.target).using(self.source).when_matched_then_delete()

    def test_get_sql_requires_source(self):
        with self.assertRaises(MergeException):
            str(PostgreSQLQuery.merge_into(self.target))

    def test_get_sql_requires_on_condition(self):
        with self.assertRaises(MergeException):
            str(PostgreSQLQuery.merge_into(self.target).using(self.source))

    def test_get_sql_requires_at_least_one_when_clause(self):
        with self.assertRaises(MergeException):
            str(self.merge())

    def test_field_references_stay_attached_to_their_table(self):
        q = (
            self.merge()
            .when_matched_then_update({"qty": self.source.qty})
            .when_not_matched_then_insert(columns=["sku"], values=[self.source.sku])
        )

        self.assertIn('UPDATE SET "qty"="s"."qty"', str(q))
        self.assertIn('VALUES ("s"."sku")', str(q))

    def test_unqualified_field_is_scoped_to_target_table(self):
        q = self.merge().when_matched_then_update({Field("qty"): 1})

        self.assertIn('UPDATE SET "qty"=1', str(q))
