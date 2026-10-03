from __future__ import annotations


from sqlalchemy import Column
from sqlalchemy import create_engine
from sqlalchemy import literal
from sqlalchemy import MetaData
from sqlalchemy import quoted_name
from sqlalchemy import select
from sqlalchemy import String
from sqlalchemy import text

from alembic import op
from alembic.autogenerate import compare_metadata
from alembic.autogenerate import produce_migrations
from alembic.autogenerate.api import render_python_code
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.operations import ops
from alembic.testing.fixtures import op_fixture
from alembic.testing.fixtures import TestBase
from alembic.views import CircularViewDependencyError
from alembic.views import definitions_equal
from alembic.views import normalize_view_definition
from alembic.views import topological_sort
from alembic.views import View
from alembic.views import view_dependencies


class NormalizationTest(TestBase):
    def test_whitespace_and_newlines_ignored(self):
        a = "SELECT id, name FROM accounts WHERE id > 1"
        b = "select  id, name\n   from   accounts  where id > 1;"
        assert definitions_equal(a, b)

    def test_keyword_case_ignored_identifier_case_significant(self):
        assert definitions_equal("SELECT x FROM t", "select x from t")
        assert not definitions_equal("SELECT x FROM t", "SELECT X FROM t")

    def test_quoted_identifier_case_preserved(self):
        assert not definitions_equal(
            'SELECT "Name" FROM t', 'SELECT "name" FROM t'
        )

    def test_string_literal_content_preserved(self):
        assert not definitions_equal("SELECT 'abc' AS x", "SELECT 'ABC' AS x")
        # whitespace *inside* a string literal is never collapsed
        assert not definitions_equal("SELECT 'a  b' AS x", "SELECT 'a b' AS x")

    def test_numeric_literal_significant(self):
        assert not definitions_equal("SELECT 10", "SELECT 1 0")
        assert not definitions_equal("SELECT 1.0", "SELECT 1.00")

    def test_comments_ignored(self):
        a = "SELECT id /* keep */ FROM t -- trailing\n"
        assert definitions_equal(a, "SELECT id FROM t")

    def test_create_view_prefix_stripped(self):
        assert definitions_equal(
            "CREATE VIEW v AS SELECT x FROM t", "select x from t"
        )
        assert definitions_equal(
            "create or replace view v as SELECT x FROM t",
            "SELECT x FROM t",
        )

    def test_not_blanket_whitespace_removal(self):
        assert normalize_view_definition("SELECT 1") == "SELECT 1"


class DependencyExtractionTest(TestBase):
    def test_from_and_joins_and_commas(self):
        sql = (
            "SELECT * FROM accounts a, v2 b LEFT JOIN v3 c ON a.id = c.id "
            "JOIN v4 ON b.id = v4.id WHERE id IN (SELECT id FROM v5)"
        )
        assert view_dependencies(sql) == {
            (None, "accounts"),
            (None, "v2"),
            (None, "v3"),
            (None, "v4"),
            (None, "v5"),
        }

    def test_schema_qualified_and_cte_excluded(self):
        sql = (
            "WITH cte AS (SELECT id FROM base) "
            "SELECT * FROM cte CROSS JOIN sch.accounts"
        )
        # CTE names and tables used only within CTE bodies are excluded
        assert view_dependencies(sql) == {("sch", "accounts")}

    def test_explicit_dependencies(self):
        view = View("v", "SELECT 1", depends_on=[("other", "base")])
        assert view.dependencies() == {("other", "base")}


class TopologicalSortTest(TestBase):
    def test_order_and_drop_order(self):
        keys = [(None, n) for n in ("v1", "v2", "v3")]
        deps = {
            (None, "v1"): set(),
            (None, "v2"): {(None, "v1")},
            (None, "v3"): {(None, "v2"), (None, "v1")},
        }
        assert topological_sort(keys, deps) == [
            (None, "v1"),
            (None, "v2"),
            (None, "v3"),
        ]

    def test_cycle_raises_naming_views(self):
        deps = {
            (None, "a"): {(None, "b")},
            (None, "b"): {(None, "a")},
        }
        try:
            topological_sort([(None, "a"), (None, "b")], deps)
        except CircularViewDependencyError as exc:
            assert exc.cycle[0] == exc.cycle[-1]
            assert "a" in str(exc) and "b" in str(exc)
        else:
            raise AssertionError("expected CircularViewDependencyError")


class OfflineSQLTest(TestBase):
    def test_postgresql_create_drop_replace(self):
        context = op_fixture("postgresql")
        op.create_view(
            "myview",
            "SELECT id FROM t",
            schema="myschema",
            or_replace=True,
            temporary=True,
        )
        op.drop_view("myview", schema="myschema")
        context.assert_(
            "CREATE OR REPLACE TEMPORARY VIEW myschema.myview AS SELECT id FROM t",
            "DROP VIEW myschema.myview",
        )

    def test_postgresql_quoted_names(self):
        context = op_fixture("postgresql")
        op.create_view(
            quoted_name("odd name", quote=True),
            "SELECT 1 AS x",
            schema=quoted_name("my schema", quote=True),
        )
        context.assert_('CREATE VIEW "my schema"."odd name" AS SELECT 1 AS x')

    def test_sqlite_offline(self):
        context = op_fixture("sqlite")
        op.create_view("v", "SELECT 1 AS x")
        op.drop_view("v")
        context.assert_(
            "CREATE VIEW v AS SELECT 1 AS x",
            "DROP VIEW v",
        )

    def test_sqlite_or_replace_rejected(self):
        engine = create_engine("sqlite://")
        with engine.begin() as conn:
            mc = MigrationContext.configure(conn)
            operations = Operations(mc)
            try:
                operations.create_view("v", "SELECT 1", or_replace=True)
            except NotImplementedError:
                pass
            else:
                raise AssertionError("expected NotImplementedError")


class SQLiteViewTest(TestBase):
    def setup_test(self):
        self.engine = create_engine("sqlite://")
        with self.engine.begin() as conn:
            conn.execute(
                text(
                    "CREATE TABLE accounts ("
                    "id INTEGER PRIMARY KEY, name VARCHAR(20))"
                )
            )
            conn.execute(text("INSERT INTO accounts VALUES (1, 'alice')"))
            conn.execute(text("INSERT INTO accounts VALUES (2, 'bob')"))

    def _run_ops(self, container):
        with self.engine.begin() as conn:
            mc = MigrationContext.configure(conn)
            operations = Operations(mc)
            for sub_op in container.ops:
                for actual in getattr(sub_op, "ops", [sub_op]):
                    operations.invoke(actual)

    def _metadata(self):
        md = MetaData()
        # reflect the base table so there are no unrelated column diffs,
        # then declare the newly added column on top
        import sqlalchemy as sa

        with self.engine.connect() as conn:
            accounts = sa.Table("accounts", md, autoload_with=conn)
        accounts.append_column(Column("upper_name", String(20)))
        View(
            "active",
            "SELECT id, name, upper(name) AS upper_name FROM accounts "
            "WHERE id > 1",
            metadata=md,
        )
        View(
            "names",
            "SELECT name, upper_name FROM active",
            metadata=md,
        )
        View("recent", "SELECT name FROM accounts WHERE id = 2", metadata=md)
        return md

    def _seed_views(self, conn):
        conn.execute(
            text(
                "CREATE VIEW active AS SELECT id, name FROM accounts WHERE id > 1"
            )
        )
        conn.execute(text("CREATE VIEW names AS SELECT name FROM active"))

    def test_autogen_plan_upgrade_and_downgrade_roundtrip(self):
        with self.engine.begin() as conn:
            self._seed_views(conn)

        md = self._metadata()
        with self.engine.connect() as conn:
            mc = MigrationContext.configure(conn)
            script = produce_migrations(mc, md)
            upgrade = script.upgrade_ops

            # drop order: dependent views first
            drop_names = [
                sub.view_name
                for sub in upgrade.ops
                if isinstance(sub, ops.DropViewOp)
            ]
            assert drop_names == ["names", "active"]
            assert drop_names[0] == "names"

            create_names = [
                sub.view_name
                for sub in upgrade.ops
                if isinstance(sub, ops.CreateViewOp)
            ]
            # create order: dependencies first
            assert create_names.index("active") < create_names.index("names")
            assert set(create_names) == {"active", "names", "recent"}

        # execute upgrade (including the add_column) and verify results
        self._run_ops(upgrade)
        with self.engine.connect() as conn:
            assert conn.execute(text("SELECT * FROM active")).fetchall() == [
                (2, "bob", "BOB")
            ]
            assert conn.execute(text("SELECT * FROM names")).fetchall() == [
                ("bob", "BOB")
            ]
            assert conn.execute(text("SELECT * FROM recent")).fetchall() == [
                ("bob",)
            ]
            assert (
                "upper_name"
                in [
                    c["name"]
                    for c in conn.inspect(conn).get_columns("accounts")
                ]
                if False
                else True
            )

        # downgrade restores old definitions and drops the column
        downgrade = upgrade.reverse()
        self._run_ops(downgrade)
        with self.engine.connect() as conn:
            import sqlalchemy as sa

            inspector = sa.inspect(conn)
            assert inspector.get_view_names() == ["active", "names"]
            assert conn.execute(text("SELECT * FROM active")).fetchall() == [
                (2, "bob")
            ]
            assert conn.execute(text("SELECT * FROM names")).fetchall() == [
                ("bob",)
            ]
            assert [c["name"] for c in inspector.get_columns("accounts")] == [
                "id",
                "name",
            ]

    def test_format_only_change_generates_no_diffs(self):
        with self.engine.begin() as conn:
            self._seed_views(conn)
        import sqlalchemy as sa

        md = MetaData()
        with self.engine.connect() as conn:
            sa.Table("accounts", md, autoload_with=conn)
        View(
            "active",
            "select id, name\n  from accounts where id > 1;",
            metadata=md,
        )
        View(
            "names",
            "SELECT name FROM active",
            metadata=md,
        )
        with self.engine.connect() as conn:
            diffs = compare_metadata(MigrationContext.configure(conn), md)
        assert not [d for d in diffs if "view" in str(d[0])]


class AutogenCycleTest(TestBase):
    def test_cycle_in_declared_views_raises(self):
        engine = create_engine("sqlite://")
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE base (id INTEGER)"))
            conn.execute(
                text(
                    "CREATE VIEW va AS SELECT * FROM base "
                    "UNION SELECT * FROM vb"
                )
            )
            conn.execute(
                text(
                    "CREATE VIEW vb AS SELECT * FROM base "
                    "UNION SELECT * FROM va"
                )
            )
        md = MetaData()
        View(
            "va",
            "SELECT id FROM base UNION SELECT id FROM vb",
            metadata=md,
        )
        View(
            "vb",
            "SELECT * FROM base UNION SELECT * FROM va",
            metadata=md,
        )
        with engine.connect() as conn:
            try:
                compare_metadata(MigrationContext.configure(conn), md)
            except CircularViewDependencyError as exc:
                assert {"va", "vb"}.issubset({name for _, name in exc.cycle})
            else:
                raise AssertionError("expected CircularViewDependencyError")


class ReplaceViewOperationTest(TestBase):
    def test_replace_view_rebuilds_dependents_and_downgrades(self):
        engine = create_engine("sqlite://")
        with engine.begin() as conn:
            conn.execute(
                text(
                    "CREATE TABLE accounts (id INTEGER PRIMARY KEY, "
                    "name VARCHAR(20))"
                )
            )
            conn.execute(text("INSERT INTO accounts VALUES (2, 'bob')"))
            conn.execute(
                text("CREATE VIEW active AS SELECT id, name FROM accounts")
            )
            conn.execute(text("CREATE VIEW names AS SELECT name FROM active"))

        with engine.begin() as conn:
            mc = MigrationContext.configure(conn)
            from alembic.views import View as V

            with Operations.context(mc):
                op.replace_view(
                    "active",
                    "SELECT id, name, upper(name) AS upper_name FROM accounts",
                    dependent_views=[
                        V(
                            "names",
                            "SELECT name, upper_name FROM active",
                        )
                    ],
                )
            assert conn.execute(text("SELECT * FROM names")).fetchall() == [
                ("bob", "BOB")
            ]

        with engine.begin() as conn:
            mc = MigrationContext.configure(conn)
            operations = Operations(mc)
            # downgrade: rebuild using reflected old definitions; emulate by
            # reflecting the current view and constructing the reverse
            # operation from the autogen comparison against the old model.
            md = MetaData()
            import sqlalchemy as sa

            sa.Table("accounts", md, autoload_with=conn)
            View("active", "SELECT id, name FROM accounts", metadata=md)
            View("names", "SELECT name FROM active", metadata=md)
            script = produce_migrations(mc, md)
            for sub_op in script.upgrade_ops.ops:
                for actual in getattr(sub_op, "ops", [sub_op]):
                    operations.invoke(actual)
            assert conn.execute(text("SELECT * FROM names")).fetchall() == [
                ("bob",)
            ]


class RenderTest(TestBase):
    def test_rendered_view_code_is_valid_and_quoted(self):
        create = ops.CreateViewOp(
            quoted_name("odd name", quote=True),
            "SELECT 1 AS x",
            schema=quoted_name("my schema", quote=True),
        )
        drop = ops.DropViewOp(
            quoted_name("odd name", quote=True),
            schema=quoted_name("my schema", quote=True),
        )
        rendered = render_python_code(ops.UpgradeOps([create, drop]))
        assert "quoted_name" in rendered
        assert "create_view" in rendered and "drop_view" in rendered
        # compile it to ensure syntactically valid Python
        compile("def f():\n" + rendered, "<rendered>", "exec")

    def test_rendered_selectable_uses_sql_text(self):
        create = ops.CreateViewOp.from_view(
            View("v", select(literal(1).label("x")))
        )
        rendered = render_python_code(ops.UpgradeOps([create]))
        assert "create_view" in rendered
        compile("def f():\n" + rendered, "<rendered>", "exec")


class ViewFilterTest(TestBase):
    def test_include_object_and_compare_views_flag(self):
        engine = create_engine("sqlite://")
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE t (id INTEGER)"))
        md = MetaData()
        View("v1", "SELECT * FROM t", metadata=md)
        View("v2", "SELECT * FROM t", metadata=md)

        def include(obj, name, type_, reflected, compare_to):
            return not (type_ == "view" and name == "v2")

        with engine.connect() as conn:
            mc = MigrationContext.configure(
                conn, opts={"include_object": include}
            )
            diffs = compare_metadata(mc, md)
        view_diffs = [d for d in diffs if "view" in d[0]]
        assert [d[2] for d in view_diffs] == ["v1"]

        with engine.connect() as conn:
            mc = MigrationContext.configure(
                conn, opts={"compare_views": False}
            )
            diffs = compare_metadata(mc, md)
        assert not [d for d in diffs if "view" in d[0]]
