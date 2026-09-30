# mypy: allow-untyped-calls

from __future__ import annotations

from collections.abc import Iterator
import contextlib
import logging
from typing import TYPE_CHECKING

from sqlalchemy import event
from sqlalchemy import schema as sa_schema
from sqlalchemy.util import OrderedSet

from .renames import prepare_rename_hints
from .renames import RenameHints
from .util import _InspectorConv
from ...operations import ops
from ...util import PriorityDispatchResult

if TYPE_CHECKING:
    from sqlalchemy.engine.reflection import Inspector
    from sqlalchemy.sql.elements import quoted_name
    from sqlalchemy.sql.schema import Table

    from ...autogenerate.api import AutogenContext
    from ...operations.ops import ModifyTableOps
    from ...operations.ops import UpgradeOps
    from ...runtime.plugins import Plugin


log = logging.getLogger(__name__)


def _autogen_for_tables(
    autogen_context: AutogenContext,
    upgrade_ops: UpgradeOps,
    schemas: set[str | None],
) -> PriorityDispatchResult:
    inspector = autogen_context.inspector

    conn_table_names: set[tuple[str | None, str]] = set()

    version_table_schema = (
        autogen_context.migration_context.version_table_schema
    )
    version_table = autogen_context.migration_context.version_table

    for schema_name in schemas:
        tables = available = set(inspector.get_table_names(schema=schema_name))
        if schema_name == version_table_schema:
            tables = tables.difference(
                [autogen_context.migration_context.version_table]
            )

        tablenames = [
            tname
            for tname in tables
            if autogen_context.run_name_filters(
                tname, "table", {"schema_name": schema_name}
            )
        ]

        conn_table_names.update((schema_name, tname) for tname in tablenames)

        inspector = autogen_context.inspector
        insp = _InspectorConv(inspector)
        insp.pre_cache_tables(schema_name, tablenames, available)

    metadata_table_names = OrderedSet(
        [(table.schema, table.name) for table in autogen_context.sorted_tables]
    ).difference([(version_table_schema, version_table)])

    _compare_tables(
        conn_table_names,
        metadata_table_names,
        inspector,
        upgrade_ops,
        autogen_context,
    )

    return PriorityDispatchResult.CONTINUE


def _compare_tables(
    conn_table_names: set[tuple[str | None, str]],
    metadata_table_names: set[tuple[str | None, str]],
    inspector: Inspector,
    upgrade_ops: UpgradeOps,
    autogen_context: AutogenContext,
) -> None:
    default_schema = inspector.bind.dialect.default_schema_name

    # tables coming from the connection will not have "schema"
    # set if it matches default_schema_name; so we need a list
    # of table names from local metadata that also have "None" if schema
    # == default_schema_name.  Most setups will be like this anyway but
    # some are not (see #170)
    metadata_table_names_no_dflt_schema = OrderedSet(
        [
            (schema if schema != default_schema else None, tname)
            for schema, tname in metadata_table_names
        ]
    )

    # to adjust for the MetaData collection storing the tables either
    # as "schemaname.tablename" or just "tablename", create a new lookup
    # which will match the "non-default-schema" keys to the Table object.
    tname_to_table = {
        no_dflt_schema: autogen_context.table_key_to_table[
            sa_schema._get_table_key(tname, schema)
        ]
        for no_dflt_schema, (schema, tname) in zip(
            metadata_table_names_no_dflt_schema, metadata_table_names
        )
    }
    metadata_table_names = metadata_table_names_no_dflt_schema
    rename_hints = prepare_rename_hints(
        autogen_context.opts.get("rename_hints"),
        conn_table_names,
        metadata_table_names,
        tname_to_table,
        inspector,
        default_schema,
    )
    autogen_context._rename_hints = rename_hints

    effective_conn_table_names = {
        rename_hints.table_key(key) for key in conn_table_names
    }
    existing_table_keys = effective_conn_table_names.intersection(
        metadata_table_names
    )

    for s, tname in metadata_table_names.difference(
        effective_conn_table_names
    ):
        name = "%s.%s" % (s, tname) if s else tname
        metadata_table = tname_to_table[(s, tname)]
        if autogen_context.run_object_filters(
            metadata_table, tname, "table", False, None
        ):
            upgrade_ops.ops.append(
                ops.CreateTableOp.from_table(metadata_table)
            )
            log.info("Detected added table %r", name)
            modify_table_ops = ops.ModifyTableOps(tname, [], schema=s)

            autogen_context.comparators.dispatch(
                "table", qualifier=autogen_context.dialect.name
            )(
                autogen_context,
                modify_table_ops,
                s,
                tname,
                None,
                metadata_table,
            )
            if not modify_table_ops.is_empty():
                upgrade_ops.ops.append(modify_table_ops)

    for rename_op in _rename_table_ops(
        rename_hints, existing_table_keys, autogen_context
    ):
        upgrade_ops.ops.append(rename_op)

    removal_metadata = sa_schema.MetaData()
    for s, tname in effective_conn_table_names.difference(
        metadata_table_names
    ):
        name = sa_schema._get_table_key(tname, s)

        # a name might be present already if a previous reflection pulled
        # this table in via foreign key constraint
        exists = name in removal_metadata.tables
        t = sa_schema.Table(tname, removal_metadata, schema=s)

        if not exists:
            event.listen(
                t,
                "column_reflect",
                # fmt: off
                autogen_context.migration_context.impl.
                _compat_autogen_column_reflect
                (inspector),
                # fmt: on
            )
            _InspectorConv(inspector).reflect_table(t)
        if autogen_context.run_object_filters(t, tname, "table", True, None):
            modify_table_ops = ops.ModifyTableOps(tname, [], schema=s)

            autogen_context.comparators.dispatch(
                "table", qualifier=autogen_context.dialect.name
            )(autogen_context, modify_table_ops, s, tname, t, None)
            if not modify_table_ops.is_empty():
                upgrade_ops.ops.append(modify_table_ops)

            upgrade_ops.ops.append(ops.DropTableOp.from_table(t))
            log.info("Detected removed table %r", name)

    existing_metadata = sa_schema.MetaData()
    conn_column_info = {}
    for s, tname in existing_table_keys:
        old_schema, old_tname = next(
            (
                (old_schema, old_tname)
                for (old_schema, old_tname), (
                    new_schema,
                    new_tname,
                ) in rename_hints.tables.items()
                if new_schema == s and new_tname == tname
            ),
            (s, tname),
        )
        name = sa_schema._get_table_key(tname, s)
        exists = name in existing_metadata.tables

        # a name might be present already if a previous reflection pulled
        # this table in via foreign key constraint
        t = sa_schema.Table(tname, existing_metadata, schema=s)
        if not exists:
            event.listen(
                t,
                "column_reflect",
                # fmt: off
                autogen_context.migration_context.impl.
                _compat_autogen_column_reflect(inspector),
                # fmt: on
            )
            insp = _InspectorConv(inspector)
            reflection_info = insp._make_reflection_info(
                tname,
                s,
                reflected_name=old_tname,
                reflected_schema=old_schema,
                renamed_tables=rename_hints.tables,
                renamed_columns=rename_hints.columns,
            )
            insp.inspector.reflect_table(
                t,
                include_columns=None,
                resolve_fks=False,
                _reflect_info=reflection_info,
            )

        conn_column_info[(s, tname)] = t

    for s, tname in sorted(
        existing_table_keys, key=lambda x: (x[0] or "", x[1])
    ):
        s = s or None
        name = "%s.%s" % (s, tname) if s else tname
        metadata_table = tname_to_table[(s, tname)]
        conn_table = existing_metadata.tables[name]

        if autogen_context.run_object_filters(
            metadata_table, tname, "table", False, conn_table
        ):
            modify_table_ops = ops.ModifyTableOps(tname, [], schema=s)
            with _compare_columns(
                s,
                tname,
                conn_table,
                metadata_table,
                modify_table_ops,
                autogen_context,
                inspector,
                rename_hints,
            ):
                autogen_context.comparators.dispatch(
                    "table", qualifier=autogen_context.dialect.name
                )(
                    autogen_context,
                    modify_table_ops,
                    s,
                    tname,
                    conn_table,
                    metadata_table,
                )
            all_pending_fks = getattr(
                autogen_context, "_pending_foreign_key_ops", None
            )
            if all_pending_fks is not None:
                pending_fks = all_pending_fks.pop((s, tname), ([], []))
                modify_table_ops.ops.extend(pending_fks[0])
                modify_table_ops.ops.extend(pending_fks[1])
            hinted_table = (s, tname) in rename_hints.tables.values() or any(
                key[0:2] == (s, tname) or value[0:2] == (s, tname)
                for key, value in rename_hints.columns.items()
            )
            if hinted_table:
                alter_column_ops = [
                    op
                    for op in modify_table_ops.ops
                    if isinstance(op, ops.AlterColumnOp)
                ]
                other_ops = [
                    op
                    for op in modify_table_ops.ops
                    if not isinstance(op, ops.AlterColumnOp)
                ]
                modify_table_ops.ops[:] = alter_column_ops + other_ops

            if not modify_table_ops.is_empty():
                upgrade_ops.ops.append(modify_table_ops)

    _order_rename_migration_ops(upgrade_ops)


def _order_rename_migration_ops(upgrade_ops) -> None:
    created = {
        (op.schema, op.table_name)
        for op in upgrade_ops.ops
        if isinstance(op, ops.CreateTableOp)
    }
    before = []
    renames = []
    after = []
    if not any(isinstance(op, ops.RenameTableOp) for op in upgrade_ops.ops):
        return

    for op in upgrade_ops.ops:
        if isinstance(op, ops.RenameTableOp):
            renames.append(op)
        elif isinstance(op, ops.CreateTableOp) or (
            isinstance(op, ops.ModifyTableOps)
            and (op.schema, op.table_name) in created
        ):
            before.append(op)
        else:
            after.append(op)
    upgrade_ops.ops[:] = before + renames + after


def _rename_table_ops(
    rename_hints: RenameHints,
    existing_table_keys: set[tuple[str | None, str]],
    autogen_context: AutogenContext,
) -> list[ops.RenameTableOp]:
    table_order = {
        (table.schema, table.name): index
        for index, table in enumerate(autogen_context.sorted_tables)
    }
    default_schema = autogen_context.dialect.default_schema_name
    result = []
    for old_key, new_key in rename_hints.tables.items():
        if new_key not in existing_table_keys or old_key == new_key:
            continue
        old_schema, old_name = old_key
        new_schema, new_name = new_key
        schema = new_schema if new_schema != default_schema else None
        result.append(ops.RenameTableOp(old_name, new_name, schema=schema))
    result.sort(key=lambda op: table_order[(op.schema, op.new_table_name)])
    return result


@contextlib.contextmanager
def _compare_columns(
    schema: str | None,
    tname: quoted_name | str,
    conn_table: Table,
    metadata_table: Table,
    modify_table_ops: ModifyTableOps,
    autogen_context: AutogenContext,
    inspector: Inspector,
    rename_hints: RenameHints,
) -> Iterator[None]:
    name = "%s.%s" % (schema, tname) if schema else tname
    metadata_col_names = OrderedSet(
        c.name for c in metadata_table.c if not c.system
    )
    metadata_cols_by_name = {
        c.name: c for c in metadata_table.c if not c.system
    }

    old_table_key = next(
        (
            old_key
            for old_key, new_key in rename_hints.tables.items()
            if new_key == (schema, tname)
        ),
        (schema, tname),
    )
    renamed_columns = {
        old_name: new_name
        for (old_schema, old_table, old_name), (
            new_schema,
            new_table,
            new_name,
        ) in rename_hints.columns.items()
        if (old_schema, old_table) == old_table_key
        and (new_schema, new_table) == (schema, tname)
    }
    conn_col_names = {}
    for reflected_name, conn_col in {c.name: c for c in conn_table.c}.items():
        old_name = next(
            (
                old_name
                for old_name, new_name in renamed_columns.items()
                if new_name == reflected_name
            ),
            reflected_name,
        )
        if autogen_context.run_name_filters(
            old_name,
            "column",
            {"table_name": old_table_key[1], "schema_name": schema},
        ):
            conn_col_names[reflected_name] = conn_col
    for cname in metadata_col_names.difference(conn_col_names):
        if autogen_context.run_object_filters(
            metadata_cols_by_name[cname], cname, "column", False, None
        ):
            modify_table_ops.ops.append(
                ops.AddColumnOp.from_column_and_tablename(
                    schema, tname, metadata_cols_by_name[cname]
                )
            )
            log.info("Detected added column '%s.%s'", name, cname)

    for colname in metadata_col_names.intersection(conn_col_names):
        metadata_col = metadata_cols_by_name[colname]
        conn_col = conn_table.c[colname]
        old_column_name = next(
            (
                old_name
                for old_name, new_name in renamed_columns.items()
                if new_name == colname
            ),
            colname,
        )
        if not autogen_context.run_object_filters(
            metadata_col,
            old_column_name,
            "column",
            False,
            conn_col,
        ):
            continue
        alter_column_op = ops.AlterColumnOp(
            tname, old_column_name, schema=schema
        )
        if old_column_name != colname:
            alter_column_op.modify_name = colname

        autogen_context.comparators.dispatch(
            "column", qualifier=autogen_context.dialect.name
        )(
            autogen_context,
            alter_column_op,
            schema,
            tname,
            colname,
            conn_col,
            metadata_col,
        )

        if alter_column_op.has_changes():
            modify_table_ops.ops.append(alter_column_op)

    yield

    for cname in set(conn_col_names).difference(metadata_col_names):
        if autogen_context.run_object_filters(
            conn_table.c[cname], cname, "column", True, None
        ):
            modify_table_ops.ops.append(
                ops.DropColumnOp.from_column_and_tablename(
                    schema, tname, conn_table.c[cname]
                )
            )
            log.info("Detected removed column '%s.%s'", name, cname)


def setup(plugin: Plugin) -> None:

    plugin.add_autogenerate_comparator(
        _autogen_for_tables,
        "schema",
        "tables",
    )
