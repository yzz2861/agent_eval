from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy import MetaData
from sqlalchemy import text
from sqlalchemy.sql.elements import quoted_name

from alembic.autogenerate import api as autogen_api
from alembic.autogenerate.compare import _produce_net_changes
from alembic.autogenerate.render import render_op_text
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.operations.ops import DowngradeOps
from alembic.operations.ops import UpgradeOps
from alembic.operations.views import CreateViewOp
from alembic.operations.views import DropViewOp
from alembic.operations.views import ReplaceViewOp
from alembic.operations.views import View
from alembic.operations.views import ViewCycleError
from alembic.operations.views import ViewRegistry
from alembic.operations.views import definitions_equal
from alembic.operations.views import extract_relation_names
from alembic.operations.views import topological_order
from alembic.testing import eq_
from alembic.testing import is_
from alembic.testing.fixtures import op_fixture
from alembic.testing.fixtures import TestBase


class SQLTokenizeTest(TestBase):
    def test_pg_style_rewritten_definition_matches(self):
        # PostgreSQL rewrites/canonicalizes view definitions (schema
        # qualification, spacing, upper keywords). Conservative compare
        # treats the relation's own schema qualification on the *table*
        # (here public.base) as significant, but simple reformatting of
        # the same body must be a non-change.
        declared = "SELECT id, val FROM base WHERE n > 1 ORDER BY id"
        reflected = (
            " SELECT id, val\n  FROM public.base\n WHERE n > 1\n"
            " ORDER BY id;"
        )
        # different relation qualification is still a change (conservative)
        is_(definitions_equal(declared, reflected), False)

        # however pure reformatting/casing without re-qualification is not
        is_(
            definitions_equal(
                declared,
                "select id, val\n from base where n > 1 order by id;",
            ),
            True,
        )

    def test_whitespace_and_comments_ignored(self):
        a = "CREATE VIEW v AS SELECT id, val FROM base WHERE n > 1"
        b = "create view v as\n select id,val -- c\n from base where n>1;"
        is_(definitions_equal(a, b), True)

    def test_unquoted_identifier_case_insensitive(self):
        is_(definitions_equal("SELECT X FROM T", "select x from t"), True)

    def test_quoted_identifier_case_significant(self):
        is_(
            definitions_equal('SELECT "X" FROM t', 'select "x" from t'),
            False,
        )

    def test_string_literal_content_significant(self):
        is_(
            definitions_equal("SELECT 'ab' FROM t", "SELECT 'AB' FROM t"),
            False,
        )
        is_(
            definitions_equal(
                "SELECT 'ab' FROM t",
                "SELECT 'a'  'b' FROM t",
            ),
            False,
        )

    def test_block_comment(self):
        is_(
            definitions_equal("SELECT /* x */ a FROM t", "select a from t"),
            True,
        )

    def test_extra_keyword_is_change(self):
        is_(
            definitions_equal("SELECT a FROM t", "SELECT DISTINCT a FROM t"),
            False,
        )

    def test_column_order_is_change(self):
        is_(
            definitions_equal("SELECT a, b FROM t", "SELECT b, a FROM t"),
            False,
        )

    def test_dollar_quoted_literal(self):
        is_(
            definitions_equal(
                "SELECT $body$ hi $body$ FROM t",
                "select $body$ hi $body$ from t",
            ),
            True,
        )


class DependencyTest(TestBase):
    def test_two_level_dependencies(self):
        eq_(
            extract_relation_names(
                "SELECT x.id FROM base x JOIN v1 o ON 1 JOIN v2 z ON 1"
            ),
            {"base", "v1", "v2"},
        )

    def test_subquery_dependency_found(self):
        eq_(
            extract_relation_names(
                "SELECT * FROM (SELECT id FROM inner_view) sq"
            ),
            {"inner_view"},
        )

    def test_cte_excluded_outer_relation_found(self):
        eq_(
            extract_relation_names(
                "WITH c AS (SELECT id FROM real_base) "
                "SELECT * FROM c JOIN real_view v ON 1"
            ),
            {"real_view"},
        )

    def test_quoted_and_schema_qualified(self):
        eq_(
            extract_relation_names('SELECT * FROM sch."Weird V"'),
            {"weird v"},
        )

    def test_topological_and_cycle(self):
        a = (None, "a")
        b = (None, "b")
        c = (None, "c")
        eq_(topological_order({a: {b}, b: {c}, c: set()}), [c, b, a])
        try:
            topological_order({a: {b}, b: {a}, c: set()})
        except ViewCycleError as err:
            eq_(err.views, [a, b])
        else:
            assert False, "expected ViewCycleError"

    def test_explicit_depends_on(self):
        from alembic.operations.views import view_dependency_edges

        a = View("a", "SELECT 1 AS x")
        b = View("b", "SELECT * FROM dynamic_source()", depends_on=("a",))
        edges = view_dependency_edges([a, b])
        eq_(edges[(None, "b")], {(None, "a")})


class OfflineSQLTest(TestBase):
    def test_postgresql_dependency_ordered_teardown_rebuild(self):
        context = op_fixture("postgresql", as_sql=True)
        with Operations.context(context) as op:
            # dependent first on the way down
            op.drop_view("v2", definition="SELECT id FROM v1")
            op.drop_view(
                "v1",
                definition="SELECT id, n FROM base WHERE n > 1",
            )
            # dependency first on the way up, with new v1 body
            op.create_view("v1", "SELECT id, n FROM base WHERE n > 2")
            op.create_view("v2", "SELECT id FROM v1")
        context.assert_(
            "DROP VIEW v2",
            "DROP VIEW v1",
            "CREATE VIEW v1 AS SELECT id, n FROM base WHERE n > 2",
            "CREATE VIEW v2 AS SELECT id FROM v1",
        )

    def test_registry_via_metadata_info(self):
        registry = ViewRegistry([View("v_info", "SELECT 1 AS x")])
        metadata = MetaData(info={"views": registry})
        engine = sa.create_engine("sqlite://")
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE b (id INTEGER)"))
            ctx = MigrationContext.configure(
                connection=conn,
                opts={
                    "target_metadata": metadata,
                    "alembic_module_prefix": "op.",
                    "sqlalchemy_module_prefix": "sa.",
                },
            )
            ac = autogen_api.AutogenContext(ctx, metadata)
            uo = UpgradeOps(ops=[])
            _produce_net_changes(ac, uo)
            names = [
                o.view_name for o in uo.ops if isinstance(o, CreateViewOp)
            ]
            eq_(names, ["v_info"])

    def test_postgresql_create_drop_offline(self):
        context = op_fixture("postgresql", as_sql=True)
        with Operations.context(context) as op:
            op.create_view(
                quoted_name("weird v", True),
                "SELECT 1 AS x",
                schema=quoted_name("my schema", True),
            )
            op.drop_view(
                quoted_name("weird v", True),
                schema=quoted_name("my schema", True),
                cascade=True,
            )
        context.assert_(
            'CREATE VIEW "my schema"."weird v" AS SELECT 1 AS x',
            'DROP VIEW "my schema"."weird v" CASCADE',
        )

    def test_sqlite_replace_is_drop_then_create(self):
        context = op_fixture("sqlite", as_sql=True)
        with Operations.context(context) as op:
            op.replace_view(
                "v",
                "SELECT 2 AS x",
                old_definition="SELECT 1 AS x",
            )
        context.assert_(
            "DROP VIEW v",
            "CREATE VIEW v AS SELECT 2 AS x",
        )

    def test_selectable_definition_compiled_offline(self):
        context = op_fixture("postgresql", as_sql=True, literal_binds=True)
        tbl = sa.table("base", sa.column("id", sa.Integer))
        stmt = sa.select(tbl.c.id).where(tbl.c.id == 5)
        with Operations.context(context) as op:
            op.create_view("v", stmt)
        context.assert_contains("CREATE VIEW v AS SELECT base.id FROM base")


def _render_ops(ctx, upgrade_ops):
    autogen_context = autogen_api.AutogenContext(ctx)
    up_lines = [render_op_text(autogen_context, o) for o in upgrade_ops.ops]
    downgrade = DowngradeOps()
    upgrade_ops.reverse_into(downgrade)
    down_lines = [render_op_text(autogen_context, o) for o in downgrade.ops]
    return up_lines, down_lines


def _produce(conn, views, metadata=None):
    if metadata is None:
        metadata = MetaData()
    ctx = MigrationContext.configure(
        connection=conn,
        opts={
            "target_views": ViewRegistry(views),
            "target_metadata": metadata,
            "alembic_module_prefix": "op.",
            "sqlalchemy_module_prefix": "sa.",
        },
    )
    upgrade_ops = UpgradeOps(ops=[])
    autogen_context = autogen_api.AutogenContext(ctx, metadata)
    _produce_net_changes(autogen_context, upgrade_ops)
    return ctx, upgrade_ops


class SQLiteViewMigrationTest(TestBase):
    def _setup(self, conn):
        conn.execute(
            text("CREATE TABLE base (id INTEGER PRIMARY KEY, n INTEGER)")
        )
        conn.execute(text("INSERT INTO base (id, n) VALUES (1, 5), (2, 0)"))
        conn.execute(
            text("CREATE VIEW v1 AS SELECT id, n FROM base WHERE n > 1")
        )
        conn.execute(text("CREATE VIEW v2 AS SELECT id FROM v1"))

    def _base_metadata(self):
        metadata = MetaData()
        sa.Table(
            "base",
            metadata,
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("n", sa.Integer),
        )
        return metadata

    def test_create_drop_views_online_queryable(self):
        engine = sa.create_engine("sqlite://")
        with engine.begin() as conn:
            conn.execute(
                text("CREATE TABLE base (id INTEGER PRIMARY KEY, n INTEGER)")
            )
            conn.execute(text("INSERT INTO base (id, n) VALUES (1, 9)"))
            mc = MigrationContext.configure(connection=conn)
            with Operations.context(mc) as op:
                op.create_view("v1", "SELECT id, n FROM base WHERE n > 1")
                op.create_view("v2", "SELECT id AS ident FROM v1")
            eq_(
                conn.execute(
                    text("SELECT ident FROM v2 ORDER BY ident")
                ).fetchall(),
                [(1,)],
            )
            cols = [
                r[1]
                for r in conn.execute(text("PRAGMA table_info(v2)")).fetchall()
            ]
            eq_(cols, ["ident"])
            with Operations.context(mc) as op:
                op.drop_view("v2")
                op.drop_view("v1")
            eq_(
                conn.execute(
                    text("SELECT name FROM sqlite_master WHERE type='view'")
                ).fetchall(),
                [],
            )

    def test_selectable_definition_online(self):
        engine = sa.create_engine("sqlite://")
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE t (id INTEGER, v INTEGER)"))
            conn.execute(text("INSERT INTO t VALUES (1, 9), (2, 0)"))
            tbl = sa.table("t", sa.column("id"), sa.column("v"))
            stmt = sa.select(tbl.c.id, tbl.c.v).where(tbl.c.v > 0)
            mc = MigrationContext.configure(connection=conn)
            with Operations.context(mc) as op:
                op.create_view("sv", stmt)
            eq_(
                conn.execute(
                    text("SELECT id, v FROM sv ORDER BY id")
                ).fetchall(),
                [(1, 9)],
            )

    def test_autogen_teardown_rebuild_upgrade_and_downgrade(self):
        engine = sa.create_engine("sqlite://")
        with engine.begin() as conn:
            self._setup(conn)
            views = [
                View("v1", "SELECT id, n FROM base WHERE n > 2"),
                View("v2", "SELECT id FROM v1"),
            ]
            ctx, upgrade_ops = _produce(conn, views, self._base_metadata())
            up_lines, down_lines = _render_ops(ctx, upgrade_ops)
            rendered = "\n".join(up_lines)
            assert rendered.index("drop_view('v2'") < rendered.index(
                "drop_view('v1'"
            )
            assert rendered.index("'v1'") < rendered.rindex("'v2'")

            with Operations.context(ctx) as op:
                for operation in upgrade_ops.ops:
                    if isinstance(
                        operation, (CreateViewOp, DropViewOp, ReplaceViewOp)
                    ):
                        op.invoke(operation)
            eq_(
                conn.execute(text("SELECT id FROM v2 ORDER BY id")).fetchall(),
                [(1,)],
            )

            downgrade = DowngradeOps()
            upgrade_ops.reverse_into(downgrade)
            with Operations.context(ctx) as op:
                for operation in downgrade.ops:
                    if isinstance(
                        operation, (CreateViewOp, DropViewOp, ReplaceViewOp)
                    ):
                        op.invoke(operation)
            conn.execute(text("INSERT INTO base (id, n) VALUES (3, 2)"))
            eq_(
                conn.execute(text("SELECT id FROM v2 ORDER BY id")).fetchall(),
                [(1,), (3,)],
            )

    def test_autogen_add_and_remove_reversible(self):
        engine = sa.create_engine("sqlite://")
        with engine.begin() as conn:
            self._setup(conn)
            views = [
                View("v1", "SELECT id, n FROM base WHERE n > 1"),
                View("v3", "SELECT n AS score FROM v1"),
            ]
            _, upgrade_ops = _produce(conn, views, self._base_metadata())
            ctx = MigrationContext.configure(connection=conn)
            with Operations.context(ctx) as op:
                for operation in upgrade_ops.ops:
                    if isinstance(
                        operation, (CreateViewOp, DropViewOp, ReplaceViewOp)
                    ):
                        op.invoke(operation)
            eq_(conn.execute(text("SELECT score FROM v3")).fetchall(), [(5,)])
            downgrade = DowngradeOps()
            upgrade_ops.reverse_into(downgrade)
            with Operations.context(ctx) as op:
                for operation in downgrade.ops:
                    if isinstance(
                        operation, (CreateViewOp, DropViewOp, ReplaceViewOp)
                    ):
                        op.invoke(operation)
            eq_(conn.execute(text("SELECT id FROM v2")).fetchall(), [(1,)])
            eq_(
                conn.execute(
                    text("SELECT name FROM sqlite_master WHERE name='v3'")
                ).fetchall(),
                [],
            )

    def test_three_level_cascade_teardown_rebuild(self):
        engine = sa.create_engine("sqlite://")
        with engine.begin() as conn:
            conn.execute(
                text("CREATE TABLE base (id INTEGER PRIMARY KEY, n INTEGER)")
            )
            conn.execute(text("INSERT INTO base (id, n) VALUES (1, 5)"))
            conn.execute(
                text("CREATE VIEW v1 AS SELECT id, n FROM base WHERE n > 0")
            )
            conn.execute(text("CREATE VIEW v2 AS SELECT id FROM v1"))
            conn.execute(text("CREATE VIEW v3 AS SELECT id FROM v2"))
            metadata = self._base_metadata()
            views = [
                View("v1", "SELECT id, n FROM base WHERE n > 2"),
                View("v2", "SELECT id FROM v1"),
                View("v3", "SELECT id FROM v2"),
            ]
            _, upgrade_ops = _produce(conn, views, metadata)
            order = [
                (type(o).__name__, getattr(o, "view_name", ""))
                for o in upgrade_ops.ops
                if type(o).__name__ in ("DropViewOp", "CreateViewOp")
            ]
            eq_(
                order,
                [
                    ("DropViewOp", "v3"),
                    ("DropViewOp", "v2"),
                    ("DropViewOp", "v1"),
                    ("CreateViewOp", "v1"),
                    ("CreateViewOp", "v2"),
                    ("CreateViewOp", "v3"),
                ],
            )
            ctx = MigrationContext.configure(connection=conn)
            with Operations.context(ctx) as op:
                for o in upgrade_ops.ops:
                    if isinstance(
                        o, (CreateViewOp, DropViewOp, ReplaceViewOp)
                    ):
                        op.invoke(o)
            eq_(conn.execute(text("SELECT id FROM v3")).fetchall(), [(1,)])

    def test_autogen_cycle_reports_views(self):
        engine = sa.create_engine("sqlite://")
        with engine.begin() as conn:
            self._setup(conn)
            views = [
                View("v1", "SELECT id FROM v2"),
                View("v2", "SELECT id FROM v1"),
            ]
            try:
                _produce(conn, views, self._base_metadata())
            except ViewCycleError as err:
                eq_({name for _, name in err.views}, {"v1", "v2"})
            else:
                assert False, "expected ViewCycleError"

    def test_quoted_view_online(self):
        engine = sa.create_engine("sqlite://")
        with engine.begin() as conn:
            conn.execute(
                text('CREATE TABLE "Base T" (id INTEGER, "V a l" INTEGER)')
            )
            conn.execute(text('INSERT INTO "Base T" VALUES (7, 3)'))
            mc = MigrationContext.configure(connection=conn)
            with Operations.context(mc) as op:
                op.create_view(
                    quoted_name("Weird View", True),
                    'SELECT "V a l" AS "Out Col" FROM "Base T"',
                )
            eq_(
                conn.execute(
                    text('SELECT "Out Col" FROM "Weird View"')
                ).fetchone(),
                (3,),
            )
            with Operations.context(mc) as op:
                op.drop_view(quoted_name("Weird View", True))

    def test_two_levels_then_base_column_change_queryable(self):
        engine = sa.create_engine("sqlite://")
        with engine.begin() as conn:
            self._setup(conn)
            mc = MigrationContext.configure(
                connection=conn, opts={"render_as_batch": True}
            )
            with Operations.context(mc) as op:
                op.drop_view("v2", definition="SELECT id FROM v1")
                op.drop_view(
                    "v1",
                    definition="SELECT id, n FROM base WHERE n > 1",
                )
                with op.batch_alter_table("base") as batch_op:
                    batch_op.add_column(sa.Column("extra", sa.Integer))
                op.create_view(
                    "v1",
                    "SELECT id, n, extra FROM base WHERE n > 1",
                )
                op.create_view("v2", "SELECT id, extra FROM v1")
            conn.execute(text("UPDATE base SET extra = 11 WHERE id = 1"))
            eq_(
                conn.execute(text("SELECT id, extra FROM v2")).fetchall(),
                [(1, 11)],
            )

    def test_view_ops_bracket_base_table_alteration(self):
        engine = sa.create_engine("sqlite://")
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE base (id INTEGER, n INTEGER)"))
            conn.execute(text("INSERT INTO base (id, n) VALUES (1, 5)"))
            conn.execute(
                text("CREATE VIEW v1 AS SELECT id, n FROM base WHERE n > 1")
            )
            conn.execute(text("CREATE VIEW v2 AS SELECT id FROM v1"))
            metadata = MetaData()
            sa.Table(
                "base",
                metadata,
                sa.Column("id", sa.Integer),
                sa.Column("n", sa.Integer),
                sa.Column("extra", sa.Integer),
            )
            views = [
                View("v1", "SELECT id, n, extra FROM base WHERE n > 1"),
                View("v2", "SELECT id, extra FROM v1"),
            ]
            _, upgrade_ops = _produce(conn, views, metadata)
            kinds = [type(o).__name__ for o in upgrade_ops.ops]
            drop_idx = [i for i, k in enumerate(kinds) if k == "DropViewOp"]
            create_idx = [
                i for i, k in enumerate(kinds) if k == "CreateViewOp"
            ]
            table_idx = [
                i for i, k in enumerate(kinds) if k == "ModifyTableOps"
            ]
            assert max(drop_idx) < min(table_idx) < min(create_idx), kinds

            mc = MigrationContext.configure(
                connection=conn, opts={"render_as_batch": True}
            )
            with Operations.context(mc) as op:
                for operation in upgrade_ops.ops:
                    if isinstance(
                        operation, (CreateViewOp, DropViewOp, ReplaceViewOp)
                    ):
                        op.invoke(operation)
                    else:
                        for sub in operation.ops:
                            op.invoke(sub)
            conn.execute(text("UPDATE base SET extra = 42 WHERE id = 1"))
            eq_(
                conn.execute(text("SELECT id, extra FROM v2")).fetchall(),
                [(1, 42)],
            )
