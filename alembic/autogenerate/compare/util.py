# mypy: allow-untyped-defs, allow-incomplete-defs, allow-untyped-calls
# mypy: no-warn-return-any, allow-any-generics
from __future__ import annotations

from collections.abc import Collection
from copy import deepcopy
from typing import Any
from typing import TYPE_CHECKING

from sqlalchemy.sql.elements import conv

if TYPE_CHECKING:
    from sqlalchemy import Table
    from sqlalchemy.engine import Inspector
    from sqlalchemy.engine.interfaces import ReflectedCheckConstraint
    from sqlalchemy.engine.interfaces import ReflectedForeignKeyConstraint
    from sqlalchemy.engine.interfaces import ReflectedIndex
    from sqlalchemy.engine.interfaces import ReflectedUniqueConstraint
    from sqlalchemy.engine.reflection import _ReflectionInfo

TableKey = tuple[str | None, str]
ColumnKey = tuple[str | None, str, str]

_INSP_KEYS = (
    "columns",
    "pk_constraint",
    "foreign_keys",
    "indexes",
    "unique_constraints",
    "table_comment",
    "check_constraints",
    "table_options",
)
_CONSTRAINT_INSP_KEYS = (
    "pk_constraint",
    "foreign_keys",
    "indexes",
    "unique_constraints",
    "check_constraints",
)


class _InspectorConv:
    __slots__ = ("inspector",)

    def __init__(self, inspector: Inspector):
        self.inspector = inspector

    def _pre_cache(
        self,
        schema: str | None,
        tablenames: list[str],
        all_available_tablenames: Collection[str],
        info_key: str,
        inspector_method: Any,
    ) -> None:

        if info_key in self.inspector.info_cache:
            return

        # heuristic vendored from SQLAlchemy 2.0
        # if more than 50% of the tables in the db are in filter_names load all
        # the tables, since it's most likely faster to avoid a filter on that
        # many tables. also if a dialect doesnt have a "multi" method then
        # return the filter names
        if tablenames and all_available_tablenames and len(tablenames) > 100:
            fraction = len(tablenames) / len(all_available_tablenames)
        else:
            fraction = None

        if (
            fraction is None
            or fraction <= 0.5
            or not self.inspector.dialect._overrides_default(
                inspector_method.__name__
            )
        ):
            optimized_filter_names = tablenames
        else:
            optimized_filter_names = None

        try:
            elements = inspector_method(
                schema=schema, filter_names=optimized_filter_names
            )
        except NotImplementedError:
            self.inspector.info_cache[info_key] = NotImplementedError
        else:
            self.inspector.info_cache[info_key] = elements

    def _return_from_cache(
        self,
        tname: str,
        schema: str | None,
        info_key: str,
        inspector_method: Any,
        apply_constraint_conv: bool = False,
        optional=True,
    ) -> Any:
        not_in_cache = object()

        if info_key in self.inspector.info_cache:
            cache = self.inspector.info_cache[info_key]
            if cache is NotImplementedError:
                if optional:
                    return {}
                else:
                    # maintain NotImplementedError as alembic compare
                    # uses these to determine classes of construct that it
                    # should not compare to DB elements
                    raise NotImplementedError()

            individual = cache.get((schema, tname), not_in_cache)

            if individual is not not_in_cache:
                if apply_constraint_conv and individual is not None:
                    return self._apply_reflectinfo_conv(individual)
                else:
                    return individual

        try:
            data = inspector_method(tname, schema=schema)
        except NotImplementedError:
            if optional:
                return {}
            else:
                raise

        if apply_constraint_conv:
            return self._apply_reflectinfo_conv(data)
        else:
            return data

    def get_unique_constraints(
        self, tname: str, schema: str | None
    ) -> list[ReflectedUniqueConstraint]:
        return self._return_from_cache(
            tname,
            schema,
            "alembic_unique_constraints",
            self.inspector.get_unique_constraints,
            apply_constraint_conv=True,
            optional=False,
        )

    def get_indexes(
        self, tname: str, schema: str | None
    ) -> list[ReflectedIndex]:
        return self._return_from_cache(
            tname,
            schema,
            "alembic_indexes",
            self.inspector.get_indexes,
            apply_constraint_conv=True,
            optional=False,
        )

    def get_foreign_keys(
        self, tname: str, schema: str | None
    ) -> list[ReflectedForeignKeyConstraint]:
        return self._return_from_cache(
            tname,
            schema,
            "alembic_foreign_keys",
            self.inspector.get_foreign_keys,
            apply_constraint_conv=True,
        )

    def get_check_constraints(
        self, tname: str, schema: str | None
    ) -> list[ReflectedCheckConstraint]:
        return self._return_from_cache(
            tname,
            schema,
            "alembic_check_constraints",
            self.inspector.get_check_constraints,
            apply_constraint_conv=True,
            optional=False,
        )

    def _apply_reflectinfo_conv(self, consts):
        if not consts:
            return consts
        for const in consts if not isinstance(consts, dict) else [consts]:
            if const["name"] is not None and not isinstance(
                const["name"], conv
            ):
                const["name"] = conv(const["name"])
        return consts

    def pre_cache_tables(
        self,
        schema: str | None,
        tablenames: list[str],
        all_available_tablenames: Collection[str],
    ) -> None:
        for key in _INSP_KEYS:
            keyname = f"alembic_{key}"
            meth = getattr(self.inspector, f"get_multi_{key}")

            self._pre_cache(
                schema,
                tablenames,
                all_available_tablenames,
                keyname,
                meth,
            )

    def _make_reflection_info(
        self,
        tname: str,
        schema: str | None,
        reflected_name: str | None = None,
        reflected_schema: str | None = None,
        renamed_tables: dict[TableKey, TableKey] | None = None,
        renamed_columns: dict[ColumnKey, ColumnKey] | None = None,
    ) -> _ReflectionInfo:
        from sqlalchemy.engine.reflection import _ReflectionInfo

        reflected_name = reflected_name or tname
        reflected_schema = (
            reflected_schema if reflected_schema is not None else schema
        )
        reflected_key = (reflected_schema, reflected_name)
        table_key = (schema, tname)
        renamed_tables = renamed_tables or {}
        renamed_columns = renamed_columns or {}

        ri = _ReflectionInfo(
            unreflectable={},
            **{
                key: {
                    table_key: deepcopy(
                        self._return_from_cache(
                            reflected_name,
                            reflected_schema,
                            f"alembic_{key}",
                            getattr(self.inspector, f"get_{key}"),
                            apply_constraint_conv=(
                                key in _CONSTRAINT_INSP_KEYS
                            ),
                        )
                    )
                }
                for key in _INSP_KEYS
            },
        )
        _remap_reflection_info(
            ri,
            reflected_key,
            table_key,
            renamed_tables,
            renamed_columns,
        )
        return ri

    def reflect_table(self, table: Table) -> None:
        ri = self._make_reflection_info(table.name, table.schema)

        self.inspector.reflect_table(
            table,
            include_columns=None,
            resolve_fks=False,
            _reflect_info=ri,
        )


def _remap_reflection_info(
    ri: _ReflectionInfo,
    reflected_key: TableKey,
    table_key: TableKey,
    renamed_tables: dict[TableKey, TableKey],
    renamed_columns: dict[ColumnKey, ColumnKey],
) -> None:
    if not renamed_tables and not renamed_columns:
        return

    local_columns = {
        old_key[2]: new_key[2]
        for old_key, new_key in renamed_columns.items()
        if (old_key[0], old_key[1]) == reflected_key
    }

    for column in ri.columns.get(table_key, []):
        column["name"] = local_columns.get(column["name"], column["name"])

    pk_constraint = ri.pk_constraint.get(table_key)
    if pk_constraint:
        pk_constraint["constrained_columns"] = [
            local_columns.get(name, name)
            for name in pk_constraint["constrained_columns"]
        ]

    for constraint in ri.foreign_keys.get(table_key, []):
        constraint["constrained_columns"] = [
            local_columns.get(name, name)
            for name in constraint["constrained_columns"]
        ]

        referred_schema = constraint.get("referred_schema")
        referred_table = constraint["referred_table"]
        referred_key = renamed_tables.get(
            (referred_schema, referred_table),
            (referred_schema, referred_table),
        )
        constraint["referred_schema"] = referred_key[0]
        constraint["referred_table"] = referred_key[1]

        referred_columns = {
            old_key[2]: new_key[2]
            for old_key, new_key in renamed_columns.items()
            if (old_key[0], old_key[1]) == (referred_schema, referred_table)
        }
        constraint["referred_columns"] = [
            referred_columns.get(name, name)
            for name in constraint["referred_columns"]
        ]

    for collection_name in ("indexes", "unique_constraints"):
        for constraint in getattr(ri, collection_name).get(table_key, []):
            for key in ("constrained_columns", "column_names"):
                if key in constraint:
                    constraint[key] = [
                        local_columns.get(name, name)
                        for name in constraint[key]
                    ]
