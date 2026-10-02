# mypy: allow-untyped-defs, allow-incomplete-defs, allow-untyped-calls
# mypy: no-warn-return-any, allow-any-generics

from __future__ import annotations

import re
from typing import Any
from typing import TYPE_CHECKING

from sqlalchemy import cast
from sqlalchemy import Computed
from sqlalchemy import JSON
from sqlalchemy import schema
from sqlalchemy import sql

from ._sqlite_trigger import rewrite_trigger_sql
from .base import alter_table
from .base import ColumnName
from .base import format_column_name
from .base import format_table_name
from .base import RenameTable
from .impl import DefaultImpl
from .. import util
from ..util import exc
from ..util.sqla_compat import compiles

if TYPE_CHECKING:
    from sqlalchemy.engine.reflection import Inspector
    from sqlalchemy.sql.compiler import DDLCompiler
    from sqlalchemy.sql.elements import Cast
    from sqlalchemy.sql.elements import ClauseElement
    from sqlalchemy.sql.schema import Column
    from sqlalchemy.sql.schema import Constraint
    from sqlalchemy.sql.schema import Table
    from sqlalchemy.sql.type_api import TypeEngine

    from ..operations.batch import ApplyBatchImpl
    from ..operations.batch import BatchOperationsImpl


class SQLiteImpl(DefaultImpl):
    __dialect__ = "sqlite"

    transactional_ddl = False
    """SQLite supports transactional DDL, but pysqlite does not:
    see: http://bugs.python.org/issue10740
    """

    def requires_recreate_in_batch(
        self, batch_op: BatchOperationsImpl
    ) -> bool:
        """Return True if the given :class:`.BatchOperationsImpl`
        would need the table to be recreated and copied in order to
        proceed.

        Normally, only returns True on SQLite when operations other
        than add_column are present.

        """
        for op in batch_op.batch:
            if op[0] == "add_column":
                col = op[1][1]
                if isinstance(
                    col.server_default, schema.DefaultClause
                ) and isinstance(col.server_default.arg, sql.ClauseElement):
                    return True
                elif (
                    isinstance(col.server_default, Computed)
                    and col.server_default.persisted
                ):
                    return True
            elif op[0] not in ("create_index", "drop_index"):
                return True
        else:
            return False

    def preserve_triggers_for_batch(
        self, batch_impl: ApplyBatchImpl
    ) -> list[tuple[str, str]]:
        if self.as_sql:
            raise exc.CommandError(
                "preserve_triggers requires a live database connection "
                "with which to reflect the triggers on the table; it "
                "cannot be used in --sql (offline) mode."
            )

        table = batch_impl.table
        table_name = str(table.name)
        final_table_name = (
            str(batch_impl.new_table_name)
            if batch_impl.new_table_name is not None
            else table_name
        )

        column_renames = {
            old_name: transfer["name"]
            for old_name, transfer in batch_impl.column_transfers.items()
            if "name" in transfer
        }
        old_column_names = {c.name for c in table.c}
        new_column_names = {c.name for c in batch_impl.columns.values()}
        dropped_columns = (
            old_column_names - new_column_names - set(column_renames)
        )

        if table.schema:
            master = "%s.sqlite_master" % (
                self.dialect.identifier_preparer.quote_schema(table.schema)
            )
        else:
            master = "sqlite_master"

        assert self.connection is not None
        rows = self.connection.exec_driver_sql(
            "SELECT name, sql FROM %s "
            "WHERE type = 'trigger' AND tbl_name = ? ORDER BY name" % master,
            (table_name,),
        ).fetchall()

        trigger_ddls = []
        for trigger_name, trigger_sql in rows:
            if not trigger_sql:
                raise exc.CommandError(
                    f"Trigger '{trigger_name}' on table "
                    f"'{table_name}' has no recorded definition and "
                    "cannot be preserved across a batch table "
                    "recreate.  Drop it before the batch operation "
                    "and recreate it afterwards, or don't use "
                    "preserve_triggers."
                )
            new_sql = rewrite_trigger_sql(
                trigger_sql,
                trigger_name=trigger_name,
                table_name=table_name,
                new_table_name=(
                    final_table_name
                    if final_table_name != table_name
                    else None
                ),
                column_renames=column_renames,
                dropped_columns=dropped_columns,
            )
            trigger_ddls.append((trigger_name, new_sql))
        return trigger_ddls

    def add_constraint(self, const: Constraint, **kw: Any):
        # attempt to distinguish between an
        # auto-gen constraint and an explicit one
        if const._create_rule is None:
            raise NotImplementedError(
                "No support for ALTER of constraints in SQLite dialect. "
                "Please refer to the batch mode feature which allows for "
                "SQLite migrations using a copy-and-move strategy."
            )
        elif const._create_rule(self):
            util.warn(
                "Skipping unsupported ALTER for "
                "creation of implicit constraint. "
                "Please refer to the batch mode feature which allows for "
                "SQLite migrations using a copy-and-move strategy."
            )

    def drop_constraint(self, const: Constraint, **kw: Any):
        if const._create_rule is None:
            raise NotImplementedError(
                "No support for ALTER of constraints in SQLite dialect. "
                "Please refer to the batch mode feature which allows for "
                "SQLite migrations using a copy-and-move strategy."
            )

    def compare_server_default(
        self,
        inspector_column: Column[Any],
        metadata_column: Column[Any],
        rendered_metadata_default: str | None,
        rendered_inspector_default: str | None,
    ) -> bool:
        if rendered_metadata_default is not None:
            rendered_metadata_default = re.sub(
                r"^\((.+)\)$", r"\1", rendered_metadata_default
            )

            rendered_metadata_default = re.sub(
                r"^\"?'(.+)'\"?$", r"\1", rendered_metadata_default
            )

        if rendered_inspector_default is not None:
            rendered_inspector_default = re.sub(
                r"^\((.+)\)$", r"\1", rendered_inspector_default
            )

            rendered_inspector_default = re.sub(
                r"^\"?'(.+)'\"?$", r"\1", rendered_inspector_default
            )

        return rendered_inspector_default != rendered_metadata_default

    def _guess_if_default_is_unparenthesized_sql_expr(
        self, expr: str | None
    ) -> bool:
        """Determine if a server default is a SQL expression or a constant.

        There are too many assertions that expect server defaults to round-trip
        identically without parenthesis added so we will add parens only in
        very specific cases.

        """
        if not expr:
            return False
        elif re.match(r"^[0-9\.]$", expr):
            return False
        elif re.match(r"^'.+'$", expr):
            return False
        elif re.match(r"^\(.+\)$", expr):
            return False
        else:
            return True

    def autogen_column_reflect(
        self,
        inspector: Inspector,
        table: Table,
        column_info: dict[str, Any],
    ) -> None:
        # SQLite expression defaults require parenthesis when sent
        # as DDL
        if self._guess_if_default_is_unparenthesized_sql_expr(
            column_info.get("default", None)
        ):
            column_info["default"] = "(%s)" % (column_info["default"],)

    def render_ddl_sql_expr(
        self, expr: ClauseElement, is_server_default: bool = False, **kw
    ) -> str:
        # SQLite expression defaults require parenthesis when sent
        # as DDL
        str_expr = super().render_ddl_sql_expr(
            expr, is_server_default=is_server_default, **kw
        )

        if (
            is_server_default
            and self._guess_if_default_is_unparenthesized_sql_expr(str_expr)
        ):
            str_expr = "(%s)" % (str_expr,)
        return str_expr

    def cast_for_batch_migrate(
        self,
        existing: Column[Any],
        existing_transfer: dict[str, TypeEngine | Cast],
        new_type: TypeEngine,
    ) -> None:
        if (
            existing.type._type_affinity is not new_type._type_affinity
            and not isinstance(new_type, JSON)
        ):
            existing_transfer["expr"] = cast(
                existing_transfer["expr"], new_type
            )

    def correct_for_autogen_constraints(
        self,
        conn_unique_constraints,
        conn_indexes,
        metadata_unique_constraints,
        metadata_indexes,
    ):
        self._skip_functional_indexes(metadata_indexes, conn_indexes)


@compiles(RenameTable, "sqlite")
def visit_rename_table(
    element: RenameTable, compiler: DDLCompiler, **kw
) -> str:
    return "%s RENAME TO %s" % (
        alter_table(compiler, element.table_name, element.schema),
        format_table_name(compiler, element.new_table_name, None),
    )


@compiles(ColumnName, "sqlite")
def visit_column_name(element: ColumnName, compiler: DDLCompiler, **kw) -> str:
    return "%s RENAME COLUMN %s TO %s" % (
        alter_table(compiler, element.table_name, element.schema),
        format_column_name(compiler, element.column_name),
        format_column_name(compiler, element.newname),
    )


# @compiles(AddColumn, 'sqlite')
# def visit_add_column(element, compiler, **kw):
#    return "%s %s" % (
#        alter_table(compiler, element.table_name, element.schema),
#        add_column(compiler, element.column, **kw)
#    )


# def add_column(compiler, column, **kw):
#    text = "ADD COLUMN %s" % compiler.get_column_specification(column, **kw)
# need to modify SQLAlchemy so that the CHECK associated with a Boolean
# or Enum gets placed as part of the column constraints, not the Table
# see ticket 98
#    for const in column.constraints:
#        text += compiler.process(AddConstraint(const))
#    return text
