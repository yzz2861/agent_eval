from django.core.exceptions import FieldError
from django.db import NotSupportedError, connection
from django.db.models import (
    Count,
    F,
    IntegerField,
    OuterRef,
    Q,
    RecursiveCTE,
    Subquery,
    Value,
)
from django.test import TestCase, skipUnlessDBFeature

from .models import Category, Person


class ManyToOneRecursiveTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.r = Category.objects.create(id=None, name="Root category", parent=None)
        cls.c = Category.objects.create(id=None, name="Child category", parent=cls.r)

    def test_m2o_recursive(self):
        self.assertSequenceEqual(self.r.child_set.all(), [self.c])
        self.assertEqual(self.r.child_set.get(name__startswith="Child").id, self.c.id)
        self.assertIsNone(self.r.parent)
        self.assertSequenceEqual(self.c.child_set.all(), [])
        self.assertEqual(self.c.parent.id, self.r.id)


class MultipleManyToOneRecursiveTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.dad = Person.objects.create(
            full_name="John Smith Senior", mother=None, father=None
        )
        cls.mom = Person.objects.create(
            full_name="Jane Smith", mother=None, father=None
        )
        cls.kid = Person.objects.create(
            full_name="John Smith Junior", mother=cls.mom, father=cls.dad
        )

    def test_m2o_recursive2(self):
        self.assertEqual(self.kid.mother.id, self.mom.id)
        self.assertEqual(self.kid.father.id, self.dad.id)
        self.assertSequenceEqual(self.dad.fathers_child_set.all(), [self.kid])
        self.assertSequenceEqual(self.mom.mothers_child_set.all(), [self.kid])
        self.assertSequenceEqual(self.kid.mothers_child_set.all(), [])
        self.assertSequenceEqual(self.kid.fathers_child_set.all(), [])


@skipUnlessDBFeature("supports_recursive_cte")
class RecursiveCTETests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.start = Category.objects.create(name="Start", parent=None)
        cls.root = Category.objects.create(name="Root", parent=cls.start)
        cls.child = Category.objects.create(name="Child", parent=cls.root)
        cls.grandchild = Category.objects.create(
            name="Grandchild", parent=cls.child
        )
        cycle_a = Category.objects.create(name="Cycle A", parent=None)
        cycle_b = Category.objects.create(name="Cycle B", parent=cycle_a)
        cycle_a.parent = cycle_b
        cycle_a.save(update_fields=["parent"])

    @classmethod
    def make_cte(cls):
        anchor = Category.objects.filter(parent__isnull=True, name="Start").values(
            "id", "parent_id", "name", depth=Value(0, output_field=IntegerField())
        )

        def recursive(previous):
            return (
                previous.filter(depth__lt=3, child_set__isnull=False)
                .annotate(next_depth=F("depth") + 1)
                .values(
                    "child_set__id",
                    "child_set__parent_id",
                    "child_set__name",
                    "next_depth",
                )
            )

        return RecursiveCTE(anchor, recursive)

    def test_filter_order_aggregate(self):
        cte = self.make_cte()
        rows = list(cte.order_by("depth", "id"))
        self.assertEqual(
            rows,
            [
                {"id": self.start.id, "parent_id": None, "name": "Start", "depth": 0},
                {
                    "id": self.root.id,
                    "parent_id": self.start.id,
                    "name": "Root",
                    "depth": 1,
                },
                {
                    "id": self.child.id,
                    "parent_id": self.root.id,
                    "name": "Child",
                    "depth": 2,
                },
                {
                    "id": self.grandchild.id,
                    "parent_id": self.child.id,
                    "name": "Grandchild",
                    "depth": 3,
                },
            ],
        )
        self.assertEqual(cte.count(), 4)
        self.assertEqual(
            cte.aggregate(total=Count("id"))["total"],
            4,
        )

    def test_model_rows_and_output_types(self):
        anchor = Category.objects.filter(name="Start").annotate(
            depth=Value(0, IntegerField())
        )
        cte = RecursiveCTE(
            anchor,
            lambda previous: previous.filter(
                depth__lt=3, child_set__isnull=False
            )
            .annotate(next_depth=F("depth") + 1)
            .values(
                "child_set__id",
                "child_set__name",
                "child_set__parent_id",
                depth=F("next_depth"),
            ),
        )
        row = cte.get(name="Root")
        self.assertEqual(row.pk, self.root.pk)
        self.assertEqual(row.parent_id, self.start.pk)
        self.assertEqual(row.depth, 1)
        self.assertIsInstance(row.depth, int)

        mismatched = RecursiveCTE(
            Category.objects.values("id"),
            lambda previous: previous.values(name=F("child_set__name")),
        )
        with self.assertRaises(FieldError):
            mismatched.query.get_compiler(connection.alias).as_sql()

    def test_subquery_and_single_declaration(self):
        cte = self.make_cte()
        queryset = Category.objects.filter(
            Q(pk__in=cte.values("id")) | Q(parent__in=cte.values("id"))
        )
        sql, params = str(queryset.query), ()
        compiler_sql, compiler_params = queryset.query.get_compiler(
            connection.alias
        ).as_sql()
        declaration = '"%s" AS (' % cte.cte.alias
        self.assertEqual(compiler_sql.count(declaration), 1)
        self.assertIn("WITH RECURSIVE", compiler_sql)
        self.assertTrue(sql)
        self.assertEqual(compiler_params, (0, "Start", 1, 3))
        tree_id = Subquery(
            cte.values("id").filter(id=OuterRef("pk")),
            output_field=IntegerField(),
        )
        annotated = Category.objects.annotate(in_tree=tree_id).filter(
            pk=self.root.pk
        )
        self.assertEqual(annotated.first().in_tree, self.root.pk)
        self.assertEqual(cte.using(connection.alias).count(), 4)
        wrapped_count = Category.objects.filter(
            pk__in=cte.values("id").order_by()
        ).count()
        self.assertEqual(wrapped_count, 4)

    def test_nested_same_name_ctes_are_scoped(self):
        def cte(anchor_name):
            anchor = Category.objects.filter(name=anchor_name).values(
                "id", "parent_id", "name", depth=Value(0, IntegerField())
            )
            recursive = (
                lambda previous: previous.filter(depth__lt=1, child_set__isnull=False)
                .annotate(next_depth=F("depth") + 1)
                .values(
                    "child_set__id",
                    "child_set__parent_id",
                    "child_set__name",
                    "next_depth",
                )
            )
            return RecursiveCTE(anchor, recursive, name="tree")

        outer = cte("Start")
        inner = cte("Start")
        queryset = Category.objects.filter(
            pk__in=outer.values("id"),
            parent__in=inner.values("id"),
        )
        sql, params = queryset.query.get_compiler(connection.alias).as_sql()
        self.assertEqual(sql.count("\"tree\" AS"), 2)
        self.assertIn("Start", params)
        self.assertEqual(params.count("Start"), 2)
        self.assertSequenceEqual(
            queryset.values_list("name", flat=True).order_by("name"),
            ["Root"],
        )

    def test_construction_without_database_access_and_immutability(self):
        with self.assertNumQueries(0):
            cte = self.make_cte()
            reused = cte.queryset()
        before = cte.query.get_compiler(connection.alias).as_sql()[0]
        filtered = cte.filter(id=self.root.id)
        after = cte.query.get_compiler(connection.alias).as_sql()[0]
        filtered_sql = filtered.query.get_compiler(connection.alias).as_sql()[0]
        self.assertEqual(before, after)
        self.assertNotEqual(before, filtered_sql)
        declaration = '"%s" AS (' % cte.cte.alias
        self.assertEqual(before.count(declaration), 1)
        self.assertIs(reused.cte, cte.cte)

    def test_unsupported_backend(self):
        cte = self.make_cte()
        supported = connection.features.supports_recursive_cte
        try:
            connection.features.supports_recursive_cte = False
            with self.assertRaises(NotSupportedError):
                cte.query.get_compiler(connection.alias).as_sql()
        finally:
            connection.features.supports_recursive_cte = supported
