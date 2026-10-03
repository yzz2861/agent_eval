import datetime
import json

from peewee import fn
from peewee import Case
from peewee import ForeignKeyField
from peewee import IntegerField
from peewee import Model
from peewee import SqliteDatabase
from peewee import TextField

from playhouse.query_description import QueryDescriptionError
from playhouse.query_description import QueryRegistry

from .base import BaseTestCase


database = SqliteDatabase(":memory:")


class QueryDescriptionBase(Model):
    class Meta:
        database = database


class QDNode(QueryDescriptionBase):
    name = TextField()
    parent = ForeignKeyField("self", backref="children", null=True)
    value = IntegerField()

    class Meta:
        database = database
        table_name = "nodes"


class QDUser(QueryDescriptionBase):
    name = TextField()
    active = IntegerField()

    class Meta:
        database = database
        table_name = "users"


registry = QueryRegistry()
registry.register_fields(QDNode)
registry.register_fields(QDUser)
registry.allow_function("COUNT")
registry.allow_function("COALESCE")
registry.allow_function("EXISTS")


class QueryDescriptionTestCase(BaseTestCase):
    def setUp(self):
        super(QueryDescriptionTestCase, self).setUp()
        database.bind([QDNode, QDUser], False, False)
        database.connect()
        database.drop_tables([QDNode, QDUser], safe=True)
        database.create_tables([QDNode, QDUser])

    def tearDown(self):
        database.drop_tables([QDNode, QDUser], safe=True)
        database.close()
        super(QueryDescriptionTestCase, self).tearDown()

    def restore(self, query):
        text = registry.dumps(query, indent=2)
        restored = registry.loads(text)
        self.assertNotIn("database", text)
        self.assertNotIn(":memory:", text)
        return text, restored

    def assertSameCompilation(self, query, bind=True):
        if bind:
            query = query.bind(database)
        original_sql, original_params = query.sql()
        text, restored = self.restore(query)
        restored_sql, restored_params = restored.bind(database).sql()
        self.assertEqual(restored_sql, original_sql)
        self.assertEqual(restored_params, original_params)
        return text, restored

    def test_columns_conditions_ordering_join_function(self):
        query = (
            QDNode
            .select(QDNode.name, fn.COUNT(QDNode.id).alias("n"))
            .join(QDUser, on=(QDNode.value == QDUser.id))
            .where((QDNode.value > 1)
                   & (QDNode.name % "a%"))
            .group_by(QDNode.name)
            .order_by(QDNode.value.desc(nulls="last"))
            .limit(5)
            .offset(2))
        text, restored = self.assertSameCompilation(query)
        self.assertIn("\"n\"", text)

    def test_shared_subquery_and_result(self):
        averages = (QDNode
                    .select(fn.COUNT(QDNode.id).alias("cnt"))
                    .alias("average_nodes"))
        exists = QDNode.select(QDNode.id).where(
            QDNode.parent == QDNode.id)
        mixed_values = QDNode.select(QDNode.value).where(QDNode.value > 1)
        query = (
            QDNode
            .select(QDNode.name, averages, fn.EXISTS(exists))
            .where(QDNode.value.in_(exists)
                   & QDNode.value.in_((3, mixed_values)))
            .order_by(QDNode.name))
        root = QDNode.create(name="root", value=3)
        QDNode.create(name="child", parent=root, value=2)
        text, restored = self.assertSameCompilation(query)
        original_rows = list(query.bind(database).tuples())
        restored_rows = list(restored.bind(database).tuples())
        self.assertEqual(restored_rows, original_rows)
        self.assertIn('"average_nodes"', text)
        self.assertGreaterEqual(text.count('"id": 3'), 2)
        self.assertEqual(text.count('"kind": "model_select"'), 4)

    def test_recursive_cte_cycle(self):
        base = (QDNode
                .select(QDNode.id, QDNode.name, QDNode.parent)
                .where(QDNode.parent.is_null())
                .cte("tree", recursive=True,
                     columns=("id", "name", "parent_id")))
        recursive = (QDNode
                     .select(QDNode.id, QDNode.name, QDNode.parent)
                     .join(base, on=(QDNode.parent == base.c.id)))
        cte = base.union_all(recursive)
        query = cte.select_from(cte.c.id, cte.c.name).order_by(cte.c.name)
        root = QDNode.create(name="root", value=1)
        child = QDNode.create(name="child", parent=root, value=1)
        text, restored = self.assertSameCompilation(query)
        original = list(query.tuples())
        recovered = list(restored.bind(database).tuples())
        self.assertEqual(recovered, original)
        self.assertEqual([row[1] for row in recovered], ["child", "root"])
        self.assertIn("WITH RECURSIVE", restored.bind(database).sql()[0])

    def test_unsupported_sql_path(self):
        from peewee import SQL
        with self.assertRaises(QueryDescriptionError) as ctx:
            registry.dumps(QDNode.select(SQL("DELETE FROM users")))
        self.assertIn("root.n0.projection.0", str(ctx.exception))

    def test_model_alias_values_function_whitelist_and_version(self):
        parent = QDNode.alias("p")
        child = QDNode.alias("c")
        query = (
            child
            .select(child.name,
                    Case(None, ((child.value > 0, "positive"),), "other"))
            .join(parent, on=(child.parent == parent.id))
            .where(child.value.in_([1, 2, 3]))
            .tuples())
        text, restored = self.assertSameCompilation(query)
        self.assertIn('"type": "int"', text)
        self.assertIn('"kind": "value"', text)
        QDNode.create(name="root", value=1)
        self.assertEqual(
            list(restored.bind(database).tuples()),
            list(query.bind(database).tuples()))

        from peewee import SQL
        bad = query.select(SQL("1"))
        with self.assertRaises(QueryDescriptionError):
            registry.dumps(bad)
        description = json.loads(text)
        description["version"] = 999
        with self.assertRaises(QueryDescriptionError):
            registry.loads(json.dumps(description))

    def test_typed_values_are_separate_from_expressions(self):
        root = QDNode.create(name="root", value=4)
        child = QDNode.create(name="child", parent=root, value=1)
        moment = datetime.datetime(2024, 1, 2, 3, 4, 5)
        query = (
            QDNode
            .select(QDNode.name)
            .where((QDNode.parent == root)
                   & (QDNode.value.in_((3, 2, b"x")))
                   & (QDNode.name == moment))
            .tuples())
        text, restored = self.assertSameCompilation(query)
        description = json.loads(text)
        self.assertTrue(any(value["type"] == "model"
                            for value in description["values"]))
        self.assertIn('"type": "bytes"', text)
        self.assertTrue(any(value["type"] == "datetime"
                            for value in description["values"]))
        self.assertEqual(
            list(restored.bind(database).tuples()),
            list(query.bind(database).tuples()))

    def test_unsafe_descriptions_and_functions_are_rejected(self):
        with self.assertRaises(QueryDescriptionError) as ctx:
            registry.dumps(QDNode.select(fn.LOWER(QDNode.name)))
        self.assertIn("not allowed", str(ctx.exception))

        text = registry.dumps(QDNode.select(QDNode.name))
        description = json.loads(text)
        description["nodes"][0]["projection"][0] = {"kind": "node_ref", "id": 99}
        with self.assertRaises(QueryDescriptionError) as ctx:
            registry.loads(json.dumps(description))
        self.assertIn("unknown node id", str(ctx.exception))

        description = json.loads(text)
        description["values"].append({"type": "import", "module": "os"})
        description["root"] = {"kind": "value", "id": 0}
        with self.assertRaises(QueryDescriptionError):
            registry.loads(json.dumps(description))
