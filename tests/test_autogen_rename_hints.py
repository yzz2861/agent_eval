from sqlalchemy import Column
from sqlalchemy import ForeignKey
from sqlalchemy import Index
from sqlalchemy import Integer
from sqlalchemy import MetaData
from sqlalchemy import create_engine
from sqlalchemy import String
from sqlalchemy import Table
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from alembic import autogenerate
from alembic.autogenerate.render import _render_cmd_body
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.operations import ops
from alembic.testing import TestBase
from alembic.testing import assert_raises
from alembic.testing import eq_
from alembic.util import CommandError


class RenameHintsTest(TestBase):
    __only_on__ = "sqlite"

    def _context(self, connection, metadata, hints):
        return MigrationContext.configure(
            connection,
            opts={"target_metadata": metadata, "rename_hints": hints},
        )

    def test_invalid_table_hints(self, connection):
        engine = create_engine("sqlite://")
        connection = engine.connect()
        metadata = MetaData()
        Table("old", metadata, Column("id", Integer, primary_key=True))
        Table("new", metadata, Column("id", Integer, primary_key=True))
        Table("other", metadata, Column("id", Integer, primary_key=True))
        metadata.create_all(connection)

        for hints, message in [
            (
                {"tables": {"old": "new", "new": "old"}},
                "Cycle detected",
            ),
            (
                {"tables": {"old": "new", "other": "new"}},
                "Multiple table rename hints map to",
            ),
            (
                {"tables": {"old": "other"}},
                "target table other already exists",
            ),
        ]:
            context = self._context(connection, metadata, hints)
            assert_raises(
                CommandError,
                autogenerate.compare_metadata,
                context,
                metadata,
            )

    def test_invalid_column_hints(self, connection):
        engine = create_engine("sqlite://")
        connection = engine.connect()
        metadata = MetaData()
        Table(
            "thing",
            metadata,
            Column("old", Integer),
            Column("new", Integer),
        )
        metadata.create_all(connection)

        for hints, message in [
            (
                {
                    "columns": {
                        "thing.old": "thing.new",
                        "thing.new": "thing.old",
                    }
                },
                "Cycle detected",
            ),
            (
                {
                    "columns": {
                        "thing.old": "thing.existing",
                    }
                },
                "target column thing.existing was not found",
            ),
            (
                {
                    "columns": {
                        "thing.old": "thing.new",
                    }
                },
                "target column thing.new already exists",
            ),
        ]:
            context = self._context(connection, metadata, hints)
            assert_raises(
                CommandError,
                autogenerate.compare_metadata,
                context,
                metadata,
            )

    def test_schema_qualified_rename_hints(self, connection):
        connection.exec_driver_sql("ATTACH DATABASE ':memory:' AS s")
        connection.exec_driver_sql("CREATE TABLE s.old_table(old_col INTEGER)")
        metadata = MetaData()
        Table("new_table", metadata, Column("new_col", Integer), schema="s")
        context = MigrationContext.configure(
            connection,
            opts={
                "target_metadata": metadata,
                "include_schemas": True,
                "rename_hints": {
                    "tables": {("s", "old_table"): ("s", "new_table")},
                    "columns": {
                        ("s", "old_table", "old_col"): (
                            "s",
                            "new_table",
                            "new_col",
                        )
                    },
                },
            },
        )
        diffs = autogenerate.compare_metadata(context, metadata)
        eq_(
            [diff[0] for diff in self._flatten(diffs)],
            ["rename_table", "rename_column"],
        )

    def test_render_table_rename(self):
        context = MigrationContext.configure(
            create_engine("sqlite://").connect()
        )
        rename = ops.RenameTableOp("old", "new")
        upgrade_ops = ops.UpgradeOps(ops=[rename])
        autogen_context = autogenerate.api.AutogenContext(
            context,
            opts={
                "alembic_module_prefix": "op.",
                "sqlalchemy_module_prefix": "sa.",
            },
        )
        upgrade = _render_cmd_body(upgrade_ops, autogen_context)
        downgrade_ops = ops.DowngradeOps(ops=[rename.reverse()])
        downgrade = _render_cmd_body(downgrade_ops, autogen_context)
        assert "op.rename_table('old', 'new')" in upgrade
        assert "op.rename_table('new', 'old')" in downgrade

    def _flatten(self, diffs):
        for diff in diffs:
            if isinstance(diff, list):
                yield from self._flatten(diff)
            else:
                yield diff

    def _invoke(self, operations, container):
        for operation in container.ops:
            if hasattr(operation, "ops"):
                with operations.batch_alter_table(
                    operation.table_name, schema=operation.schema
                ) as batch_operations:
                    for nested_operation in operation.ops:
                        batch_operations.invoke(nested_operation)
            else:
                operations.invoke(operation)

    def _fixture(self, connection):
        connection.exec_driver_sql(
            "CREATE TABLE old_parent ("
            "id INTEGER NOT NULL PRIMARY KEY, "
            "old_name VARCHAR(20) NOT NULL DEFAULT 'x', "
            "old_size INTEGER NOT NULL)"
        )
        connection.exec_driver_sql(
            "CREATE TABLE old_child ("
            "id INTEGER NOT NULL PRIMARY KEY, "
            "old_parent_id INTEGER NOT NULL, "
            "old_note VARCHAR(10), "
            "CONSTRAINT fk_old_child_old_parent_id_old_parent "
            "FOREIGN KEY(old_parent_id) REFERENCES old_parent(id))"
        )
        connection.exec_driver_sql(
            "CREATE INDEX ix_old_child_old_note ON old_child(old_note)"
        )
        connection.execute(
            text(
                "INSERT INTO old_parent(id, old_name, old_size) "
                "VALUES (1, 'alice', 7), (2, 'bob', 9)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO old_child(id, old_parent_id, old_note) "
                "VALUES (10, 1, 'first'), (11, 2, 'second')"
            )
        )

        metadata = MetaData(
            naming_convention={
                "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s"
            }
        )
        Table(
            "new_parent",
            metadata,
            Column("id", Integer, primary_key=True),
            Column(
                "new_name",
                String(20),
                nullable=False,
                server_default="x",
            ),
            Column("old_size", String(20), nullable=False),
        )
        Table(
            "new_child",
            metadata,
            Column("id", Integer, primary_key=True),
            Column(
                "new_parent_id",
                Integer,
                ForeignKey("new_parent.id"),
                nullable=False,
            ),
            Column("new_note", String(10)),
            Index("ix_old_child_old_note", "new_note"),
        )
        return metadata

    def _migration_script(self, connection, metadata, batch=False):
        context = MigrationContext.configure(
            connection,
            opts={
                "target_metadata": metadata,
                "render_as_batch": batch,
                "rename_hints": {
                    "tables": {
                        "old_parent": "new_parent",
                        "old_child": "new_child",
                    },
                    "columns": {
                        (None, "old_parent", "old_name"): (
                            None,
                            "new_parent",
                            "new_name",
                        ),
                        "old_child.old_parent_id": "new_child.new_parent_id",
                        "old_child.old_note": "new_child.new_note",
                    },
                },
            },
        )
        return context, autogenerate.produce_migrations(context, metadata)

    def _assert_rows(self, connection, upgraded):
        parent_table = "new_parent" if upgraded else "old_parent"
        child_table = "new_child" if upgraded else "old_child"
        parent_name = "new_name" if upgraded else "old_name"
        child_parent = "new_parent_id" if upgraded else "old_parent_id"
        child_note = "new_note" if upgraded else "old_note"

        eq_(
            connection.execute(
                text(
                    f"SELECT id, {parent_name}, old_size FROM {parent_table} "
                    "ORDER BY id"
                )
            ).all(),
            [
                (1, "alice", "7" if upgraded else 7),
                (2, "bob", "9" if upgraded else 9),
            ],
        )
        eq_(
            connection.execute(
                text(
                    f"SELECT id, {child_parent}, {child_note} "
                    f"FROM {child_table} ORDER BY id"
                )
            ).all(),
            [(10, 1, "first"), (11, 2, "second")],
        )

    def test_sqlite_roundtrip_batch(self, connection):
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")
        metadata = self._fixture(connection)
        context, script = self._migration_script(
            connection, metadata, batch=True
        )
        eq_(
            [diff[0] for diff in self._flatten(script.upgrade_ops.as_diffs())],
            [
                "rename_table",
                "rename_table",
                "rename_column",
                "rename_column",
                "remove_fk",
                "add_fk",
                "rename_column",
                "modify_type",
            ],
        )

        self._invoke(Operations(context), script.upgrade_ops)

        self._assert_rows(connection, True)
        eq_(
            connection.exec_driver_sql(
                "PRAGMA foreign_key_list(new_child)"
            ).cursor.fetchall(),
            [
                (
                    0,
                    0,
                    "new_parent",
                    "new_parent_id",
                    "id",
                    "NO ACTION",
                    "NO ACTION",
                    "NONE",
                )
            ],
        )
        eq_(
            connection.exec_driver_sql("PRAGMA foreign_keys").scalar(),
            1,
        )
        assert_raises(
            IntegrityError,
            connection.exec_driver_sql,
            "INSERT INTO new_child(id, new_parent_id, new_note) "
            "VALUES (12, 99, 'bad')",
        )

        self._invoke(Operations(context), script.downgrade_ops)

        self._assert_rows(connection, False)
