import unittest

from pypika import (
    Field,
    MergeWhenMatched,
    MergeWhenNotMatched,
    MergeWhenNotMatchedBySource,
    Parameter,
    QmarkParameter,
    Table,
    QueryException,
)
from pypika.dialects import MSSQLQuery, PostgreSQLQuery


class PostgreSQLMergeTests(unittest.TestCase):
    target = Table("customers").as_("c")
    source = Table("customer_updates").as_("u")

    def test_compile_conditional_update_delete_and_insert(self):
        update_branch = (
            MergeWhenMatched(self.target.updated_at < self.source.updated_at)
            .update()
            .set(Field("name"), self.source.name)
            .set(Field("updated_at"), Parameter(":updated_at"))
        )
        delete_branch = MergeWhenMatched(self.source.deleted_at.isnotnull()).delete()
        insert_branch = (
            MergeWhenNotMatched().insert().columns(Field("id"), Field("name")).values(self.source.id, self.source.name)
        )

        query = (
            PostgreSQLQuery.merge(self.target)
            .using(self.source)
            .on(self.target.id == self.source.id)
            .when(update_branch)
            .when(delete_branch)
            .when(insert_branch)
        )

        self.assertEqual(
            'MERGE INTO "customers" "c" '
            'USING "customer_updates" "u" '
            'ON "c"."id"="u"."id" '
            'WHEN MATCHED AND "c"."updated_at"<"u"."updated_at" '
            'THEN UPDATE SET "name"="u"."name","updated_at"=:updated_at '
            'WHEN MATCHED AND "u"."deleted_at" IS NOT NULL THEN DELETE '
            'WHEN NOT MATCHED THEN INSERT ("id","name") VALUES ("u"."id","u"."name")',
            query.get_sql(),
        )

    def test_compile_aliased_subquery_source_and_parameters(self):
        staging = Table("staging")
        subquery = (
            PostgreSQLQuery.from_(staging).select(staging.id, staging.name).where(staging.import_id == 123).as_("u")
        )
        insert_branch = (
            MergeWhenNotMatched().insert().columns(Field("id"), Field("name")).values(subquery.id, subquery.name)
        )

        parameter = QmarkParameter()
        query = PostgreSQLQuery.merge(self.target).using(subquery).on(self.target.id == subquery.id).when(insert_branch)
        sql = query.get_sql(parameter=parameter)

        self.assertEqual(
            'MERGE INTO "customers" "c" '
            'USING (SELECT "id","name" FROM "staging" WHERE "import_id"=?) "u" '
            'ON "c"."id"="u"."id" '
            'WHEN NOT MATCHED THEN INSERT ("id","name") VALUES ("u"."id","u"."name")',
            sql,
        )
        self.assertEqual([123], parameter.get_parameters())


class MSSQLMergeTests(unittest.TestCase):
    target = Table("customers", schema="dbo")
    source = Table("staging_customer_updates").as_("u")

    def test_compile_matched_target_and_source_branches(self):
        update_branch = MergeWhenMatched(self.source.deleted_at.isnull()).update().set(Field("name"), self.source.name)
        insert_branch = (
            MergeWhenNotMatched().insert().columns(Field("id"), Field("name")).values(self.source.id, self.source.name)
        )
        delete_branch = MergeWhenNotMatchedBySource().delete()

        query = (
            MSSQLQuery.merge(self.target, self.source, self.target.id == self.source.id)
            .when(update_branch)
            .when(insert_branch)
            .when(delete_branch)
        )

        self.assertEqual(
            'MERGE "dbo"."customers" '
            'USING "staging_customer_updates" "u" '
            'ON "customers"."id"="u"."id" '
            'WHEN MATCHED AND "u"."deleted_at" IS NULL THEN UPDATE SET "name"="u"."name" '
            'WHEN NOT MATCHED BY TARGET THEN INSERT ("id","name") VALUES ("u"."id","u"."name") '
            'WHEN NOT MATCHED BY SOURCE THEN DELETE;',
            query.get_sql(),
        )

    def test_target_assignments_compile_as_bare_columns_when_target_is_aliased(self):
        target = Table("customers").as_("c")
        update_branch = MergeWhenMatched().update().set(target.name, self.source.name)
        insert_branch = MergeWhenNotMatched().insert().columns(target.id).values(self.source.id)

        query = (
            MSSQLQuery.merge(target, self.source, target.id == self.source.id).when(update_branch).when(insert_branch)
        )

        self.assertIn('THEN UPDATE SET "name"="u"."name"', query.get_sql())
        self.assertIn('THEN INSERT ("id") VALUES ("u"."id")', query.get_sql())

    def test_compile_aliased_subquery_source(self):
        staging = Table("staging")
        subquery = MSSQLQuery.from_(staging).select(staging.id, staging.name).as_("u")
        insert_branch = (
            MergeWhenNotMatched().insert().columns(Field("id"), Field("name")).values(subquery.id, subquery.name)
        )

        query = MSSQLQuery.merge(self.target).using(subquery).on(self.target.id == subquery.id).when(insert_branch)

        self.assertEqual(
            'MERGE "dbo"."customers" '
            'USING (SELECT "id","name" FROM "staging") "u" '
            'ON "customers"."id"="u"."id" '
            'WHEN NOT MATCHED BY TARGET THEN INSERT ("id","name") VALUES ("u"."id","u"."name");',
            query.get_sql(),
        )


class MergeValidationTests(unittest.TestCase):
    target = Table("customers").as_("c")
    source = Table("updates").as_("u")

    def test_unconditional_branch_makes_later_same_type_branch_unreachable(self):
        query = (
            PostgreSQLQuery.merge(self.target, self.source, self.target.id == self.source.id)
            .when(MergeWhenMatched().delete())
            .when(MergeWhenMatched(self.source.deleted_at.isnotnull()).delete())
        )

        with self.assertRaisesRegex(QueryException, "unreachable"):
            query.get_sql()

    def test_postgresql_does_not_support_not_matched_by_source(self):
        query = PostgreSQLQuery.merge(self.target, self.source, self.target.id == self.source.id).when(
            MergeWhenNotMatchedBySource().delete()
        )

        with self.assertRaisesRegex(QueryException, "not supported"):
            query.get_sql()

    def test_not_matched_cannot_delete(self):
        query = PostgreSQLQuery.merge(self.target, self.source, self.target.id == self.source.id).when(
            MergeWhenNotMatched().delete()
        )

        with self.assertRaisesRegex(QueryException, "DELETE is not supported"):
            query.get_sql()

    def test_matched_cannot_insert(self):
        query = PostgreSQLQuery.merge(self.target, self.source, self.target.id == self.source.id).when(
            MergeWhenMatched().insert().columns(Field("id")).values(self.source.id)
        )

        with self.assertRaisesRegex(QueryException, "INSERT is not supported"):
            query.get_sql()

    def test_branch_without_action_is_invalid(self):
        query = PostgreSQLQuery.merge(self.target, self.source, self.target.id == self.source.id).when(
            MergeWhenMatched()
        )

        with self.assertRaisesRegex(QueryException, "exactly one"):
            query.get_sql()

    def test_insert_column_and_value_counts_must_match(self):
        branch = MergeWhenNotMatched().insert().columns(Field("id"), Field("name")).values(self.source.id)
        query = PostgreSQLQuery.merge(self.target, self.source, self.target.id == self.source.id).when(branch)

        with self.assertRaisesRegex(QueryException, "counts must match"):
            query.get_sql()

    def test_unqualified_insert_value_is_invalid(self):
        branch = MergeWhenNotMatched().insert().columns(Field("id")).values(Field("id"))
        query = PostgreSQLQuery.merge(self.target, self.source, self.target.id == self.source.id).when(branch)

        with self.assertRaisesRegex(QueryException, "must be qualified"):
            query.get_sql()

    def test_rejects_second_action_in_branch(self):
        with self.assertRaisesRegex(QueryException, "only contain one action"):
            MergeWhenMatched().delete().update()

    def test_rejects_duplicate_update_target_columns(self):
        branch = MergeWhenMatched().update().set(Field("id"), self.source.id).set(Field("id"), self.source.id)
        query = PostgreSQLQuery.merge(self.target, self.source, self.target.id == self.source.id).when(branch)

        with self.assertRaisesRegex(QueryException, "Duplicate MERGE target column: id"):
            query.get_sql()

    def test_rejects_duplicate_insert_target_columns(self):
        branch = MergeWhenNotMatched().insert().columns(Field("id"), Field("id")).values(self.source.id, self.source.id)
        query = PostgreSQLQuery.merge(self.target, self.source, self.target.id == self.source.id).when(branch)

        with self.assertRaisesRegex(QueryException, "Duplicate MERGE target column: id"):
            query.get_sql()

    def test_rejects_unqualified_on_field(self):
        query = PostgreSQLQuery.merge(self.target, self.source, Field("id") == self.source.id)

        with self.assertRaisesRegex(QueryException, "ON fields must belong"):
            query.when(MergeWhenMatched().delete()).get_sql()

    def test_rejects_foreign_field_in_insert_values(self):
        other = Table("other").as_("o")
        branch = MergeWhenNotMatched().insert().columns(Field("id")).values(other.id)
        query = PostgreSQLQuery.merge(self.target, self.source, self.target.id == self.source.id).when(branch)

        with self.assertRaisesRegex(QueryException, "does not belong"):
            query.get_sql()

    def test_rejects_unaliased_subquery_source(self):
        subquery = PostgreSQLQuery.from_(Table("staging")).select("id")

        with self.assertRaisesRegex(QueryException, "subquery sources must have an alias"):
            PostgreSQLQuery.merge(self.target).using(subquery)

    def test_mssql_requires_branches_to_be_grouped_by_match_type(self):
        query = (
            MSSQLQuery.merge(self.target, self.source, self.target.id == self.source.id)
            .when(MergeWhenNotMatched().insert().columns(Field("id")).values(self.source.id))
            .when(MergeWhenMatched().delete())
        )

        with self.assertRaisesRegex(QueryException, "grouped by match type"):
            query.get_sql()
