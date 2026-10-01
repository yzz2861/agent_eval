from django.db.models import (
    Count,
    Exists,
    F,
    IntegerField,
    OuterRef,
    Q,
    RecursiveCTE,
    Subquery,
    Value,
)
from django.test import TestCase, skipUnlessDBFeature

from .models import Tag


def make_tag_cte():
    anchor = Tag.objects.filter(parent__isnull=True).values(
        "id",
        depth=Value(0, output_field=IntegerField()),
    )

    def recursive(previous):
        return previous.join(
            Tag.objects.values(
                "id",
                depth=previous.col("depth") + 1,
            ),
            previous.col("depth").lt(3),
            id=F("parent_id"),
        )

    return RecursiveCTE(anchor, recursive, name="tag_tree")


class RecursiveCTETests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.root = Tag.objects.create(name="root")
        cls.child = Tag.objects.create(name="child", parent=cls.root)
        cls.grandchild = Tag.objects.create(
            name="grandchild", parent=cls.child
        )

    def test_filter_order_aggregate(self):
        cte = make_tag_cte()
        qs = cte.queryset().filter(id__in=[self.root.id, self.child.id])
        qs = qs.order_by("depth", "id").values("depth")
        self.assertSequenceEqual(qs, [{"depth": 0}, {"depth": 1}])

    @skipUnlessDBFeature("supports_recursive_cte")
    def test_cycle_termination(self):
        cycle_one = Tag.objects.create(name="cycle-one")
        cycle_two = Tag.objects.create(name="cycle-two", parent=cycle_one)
        cycle_one.parent = cycle_two
        cycle_one.save(update_fields=["parent"])
        cycle_one.parent = self.child
        cycle_one.save(update_fields=["parent"])

        qs = make_tag_cte().queryset().filter(depth=2).order_by("id")
        self.assertCountEqual(
            qs,
            [
                {"id": self.grandchild.id, "depth": 2},
                {"id": cycle_one.id, "depth": 2},
            ],
        )
        qs = make_tag_cte().queryset().filter(id__in=[cycle_one.id, cycle_two.id])
        self.assertCountEqual(
            qs.order_by("id", "depth"),
            [
                {"id": cycle_one.id, "depth": 2},
                {"id": cycle_two.id, "depth": 3},
            ],
        )

    def test_output_field_conversion(self):
        cte = make_tag_cte()
        depth = cte.queryset().filter(id=self.grandchild.id).get()["depth"]
        self.assertIsInstance(depth, int)
        self.assertEqual(depth, 2)

    def test_aggregate(self):
        cte = make_tag_cte()
        self.assertEqual(cte.queryset().count(), 3)
        self.assertEqual(
            cte.queryset().aggregate(total=Count("id")),
            {"total": 3},
        )

    def test_parameters_and_declaration_deduplicated(self):
        cte = make_tag_cte()
        queryset = Tag.objects.filter(
            Exists(cte.queryset().filter(id=OuterRef("pk")))
            | Exists(cte.queryset().filter(depth=Value(0)))
        )
        sql, params = queryset.query.sql_with_params()
        self.assertEqual(sql.count("WITH RECURSIVE"), 1)
        self.assertEqual(sql.count(" AS (SELECT"), 1)
        self.assertEqual(params, (0, 1, 3, 1, 1, 0))

    def test_scalar_subquery_hoists_cte(self):
        cte = make_tag_cte()
        queryset = Tag.objects.annotate(
            depth=Subquery(
                cte.queryset()
                .filter(id=OuterRef("pk"))
                .order_by("-depth")
                .values("depth")[:1],
                output_field=IntegerField(),
            )
        ).filter(pk=self.child.pk)
        sql, params = queryset.query.sql_with_params()
        self.assertEqual(sql.count("WITH RECURSIVE"), 1)
        self.assertNotIn("(WITH RECURSIVE", sql)
        self.assertEqual(params, (0, 1, 3, 2))
        self.assertEqual(queryset.get().depth, 1)

    def test_nested_scalar_subquery_relabels_recursive_join(self):
        cte = make_tag_cte()
        inner = cte.queryset().filter(id=OuterRef("pk")).values("depth")[:1]
        middle = Tag.objects.annotate(
            depth=Subquery(inner, output_field=IntegerField())
        )
        outer = Tag.objects.filter(
            pk__in=middle.filter(depth__gte=0).values("pk")
        )
        sql, _ = outer.query.sql_with_params()
        self.assertNotIn(f"{cte.sql_name} ON", sql)
        self.assertEqual(sql.count("WITH RECURSIVE"), 1)

    def test_nested_same_name_ctes(self):
        first = make_tag_cte()
        second = make_tag_cte()
        self.assertNotEqual(first.sql_name, second.sql_name)
        queryset = Tag.objects.filter(
            Exists(first.queryset().filter(id=OuterRef("pk")))
            & Exists(second.queryset().filter(id=OuterRef("pk")))
        )
        sql, params = queryset.query.sql_with_params()
        self.assertIn(f'"{first.sql_name}" ("id", "depth")', sql)
        self.assertIn(f'"{second.sql_name}" ("id", "depth")', sql)
        self.assertEqual(params, (0, 1, 3, 1, 0, 1, 3, 1))

    def test_cte_dependency_declared_before_recursive_cte(self):
        roots = Tag.objects.filter(parent__isnull=True).values(
            "id",
            depth=Value(0, output_field=IntegerField()),
        )
        root_cte = RecursiveCTE(
            roots,
            lambda previous: previous.join(
                Tag.objects.values(
                    "id",
                    depth=previous.col("depth") + 1,
                ),
                id=F("parent_id"),
            ),
            name="root_paths",
        )

        anchor = root_cte.queryset().filter(id=self.root.id)
        dependent = RecursiveCTE(
            anchor,
            lambda previous: previous.join(
                Tag.objects.values(
                    "id",
                    depth=previous.col("depth") + 1,
                ),
                id=F("parent_id"),
            ),
            name="selected_paths",
        )
        sql, _ = dependent.queryset().query.sql_with_params()
        root_name = root_cte.sql_name
        selected_name = dependent.sql_name
        self.assertLess(sql.index(root_name), sql.index(selected_name))
        self.assertEqual(sql.count(f'"{root_name}" ("id", "depth")'), 1)

    def test_recursive_join_on_q_object(self):
        anchor = Tag.objects.filter(parent__isnull=True).values(
            "id",
            depth=Value(0, output_field=IntegerField()),
        )

        def recursive(previous):
            return previous.join(
                Tag.objects.values(
                    "id",
                    depth=previous.col("depth") + 1,
                ),
                on=Q(previous.col("id").exact(F("parent_id")))
                & Q(previous.col("depth").lt(3)),
            )

        cte = RecursiveCTE(anchor, recursive, name="q_join_tree")
        qs = cte.queryset().filter(id=self.child.id)
        sql, params = qs.query.sql_with_params()
        self.assertIn("INNER JOIN", sql)
        self.assertEqual(params, (0, 1, 3, 2))
        self.assertEqual(qs.get()["depth"], 1)

    def test_reuse_does_not_mutate_source_queryset(self):
        cte = make_tag_cte()
        source = cte.queryset()
        filtered = source.filter(id=self.root.id)
        source_sql, _ = source.query.sql_with_params()
        filtered_sql, _ = filtered.query.sql_with_params()
        self.assertEqual(source_sql.count("WHERE"), 1)
        self.assertEqual(filtered_sql.count("WHERE"), 2)

    def test_construction_does_not_query_database(self):
        with self.assertNumQueries(0):
            cte = make_tag_cte()
            cte.queryset().filter(id=1).order_by("depth").query.sql_with_params()
