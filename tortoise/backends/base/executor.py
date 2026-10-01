from __future__ import annotations

import asyncio
import datetime
import decimal
from collections.abc import Callable, Iterable, Sequence
from copy import copy
from typing import TYPE_CHECKING, Any, cast

from pypika_tortoise import JoinType, Parameter, Table
from pypika_tortoise.queries import QueryBuilder

from tortoise.exceptions import OperationalError, UnSupportedError
from tortoise.expressions import Expression, ResolveContext
from tortoise.fields.base import DatabaseDefault
from tortoise.fields.relational import (
    BackwardFKRelation,
    BackwardOneToOneRelation,
    ManyToManyFieldInstance,
    RelationalField,
)
from tortoise.query_utils import QueryModifier

if TYPE_CHECKING:  # pragma: nocoverage
    from tortoise.backends.base.client import BaseDBAsyncClient
    from tortoise.filters import FilterInfoDict
    from tortoise.models import Model
    from tortoise.query_utils import Prefetch
    from tortoise.queryset import QuerySet

EXECUTOR_CACHE: dict[
    tuple[str, str | None, str],
    tuple[list, str, list, str, str, dict[str, str]],
] = {}

CHUNK_SIZE = 2000


class BaseExecutor:
    FILTER_FUNC_OVERRIDE: dict[Callable, Callable] = {}
    EXPLAIN_PREFIX: str = "EXPLAIN"
    DB_NATIVE = {bytes, str, int, float, decimal.Decimal, datetime.datetime, datetime.date}

    def __init__(
        self,
        model: type[Model],
        db: BaseDBAsyncClient,
        prefetch_map: dict[str, set[str | Prefetch]] | None = None,
        prefetch_queries: dict[str, list[tuple[str | None, QuerySet]]] | None = None,
        select_related_idx: (
            list[tuple[type[Model], int, str, type[Model], Iterable[str | None]]] | None
        ) = None,
    ) -> None:
        self.model = model
        self.db: BaseDBAsyncClient = db
        self.prefetch_map = prefetch_map or {}
        self._prefetch_queries = prefetch_queries or {}
        self.select_related_idx = select_related_idx
        key = (self.db.connection_name, self.model._meta.schema, self.model._meta.db_table)
        if key not in EXECUTOR_CACHE:
            self.regular_columns, columns = self._prepare_insert_columns()
            self.insert_query = str(self._prepare_insert_statement(columns))
            self.regular_columns_all = self.regular_columns
            self.insert_query_all = self.insert_query
            if self.model._meta.generated_db_fields:
                self.regular_columns_all, columns_all = self._prepare_insert_columns(
                    include_generated=True
                )
                self.insert_query_all = str(
                    self._prepare_insert_statement(columns_all, has_generated=False)
                )

            table = self.model._meta.basetable
            basequery = cast(QueryBuilder, self.model._meta.basequery)
            self.delete_query = str(
                basequery.where(table[self.model._meta.db_pk_column] == self.parameter(0)).delete()
            )
            self.update_cache: dict[str, str] = {}

            EXECUTOR_CACHE[key] = (
                self.regular_columns,
                self.insert_query,
                self.regular_columns_all,
                self.insert_query_all,
                self.delete_query,
                self.update_cache,
            )

        else:
            (
                self.regular_columns,
                self.insert_query,
                self.regular_columns_all,
                self.insert_query_all,
                self.delete_query,
                self.update_cache,
            ) = EXECUTOR_CACHE[key]

    async def execute_explain(
        self, sql: str, output_fmt: str | None = None, **options: bool
    ) -> Any:
        if output_fmt:
            raise UnSupportedError("This database does not support different explain formats")

        if options:
            raise UnSupportedError("This database does not support explain options")

        sql = " ".join((self.EXPLAIN_PREFIX, sql))
        return (await self.db.execute_query(sql))[1]

    async def execute_select(
        self,
        sql: str,
        values: list | None = None,
        custom_fields: list | None = None,
    ) -> list:
        _, raw_results = await self.db.execute_query(sql, values)
        instance_list = await self._instances_from_rows(list(raw_results), custom_fields)
        await self._execute_prefetch_queries(instance_list)
        return instance_list

    async def _instances_from_rows(
        self, raw_results: Sequence, custom_fields: list | None = None
    ) -> list:
        """Build model instances from raw DB rows (including select_related rows)."""
        instance_list = []
        if self.select_related_idx:
            _split_cache: dict[str, str] = {}
        for row_idx, row in enumerate(raw_results):
            if row_idx != 0 and row_idx % CHUNK_SIZE == 0:
                # Forcibly yield to the event loop to avoid blocking the event loop
                # when selecting a large number of rows
                await asyncio.sleep(0)

            if self.select_related_idx:
                _, current_idx, _, _, path = self.select_related_idx[0]
                row_items = list(dict(row).items())
                instance: Model = self.model._init_from_db(**dict(row_items[:current_idx]))
                instances: dict[Any, Any] = {path: instance}
                for model, index, *__, full_path in self.select_related_idx[1:]:
                    (*path, attr) = full_path
                    related_items = row_items[current_idx : current_idx + index]
                    if any(v for _, v in related_items):
                        related_kwargs = {}
                        for k, v in related_items:
                            fname = _split_cache.get(k)
                            if fname is None:
                                fname = _split_cache[k] = k.split(".", 1)[1]
                            related_kwargs[fname] = v
                        obj = model._init_from_db(**related_kwargs)
                    elif index == 0:
                        # 0 signals that an empty "filler" object should be created in the case
                        # where a field of related model is selected but model itself isn't,
                        # e.g. .only("relatedmodel__field")
                        obj = model._init_from_db()
                    else:
                        obj = None
                    target = instances.get(tuple(path))
                    if target is not None:
                        object.__setattr__(target, f"_{attr}", obj)
                    if obj is not None:
                        instances[(*path, attr)] = obj
                    current_idx += index
            else:
                instance = self.model._init_from_db(**row)
            if custom_fields:
                for field in custom_fields:
                    object.__setattr__(instance, field, row[field])
            instance_list.append(instance)
        return instance_list

    def execute_select_stream(
        self,
        sql: str,
        values: list | None = None,
        custom_fields: list | None = None,
        batch_size: int = 100,
    ):
        """Yield batches of model instances from a lazily-read server cursor.

        Relations from ``prefetch_related`` are loaded once per batch, with a
        single query per relation, before the batch is handed to the consumer.
        Rows beyond the current batch are never read until the consumer asks
        for the next one.
        """
        return _ModelBatchStream(self, sql, values, custom_fields, batch_size)

    async def execute_union(
        self, sql: str, app_field: str, model_field: str, models: set[type[Model]]
    ) -> list:
        _, raw_results = await self.db.execute_query(sql)
        instance_list = []

        for row_idx, row in enumerate(raw_results):
            if row_idx != 0 and row_idx % CHUNK_SIZE == 0:
                # Forcibly yield to the event loop to avoid blocking the event loop
                # when selecting a large number of rows
                await asyncio.sleep(0)

            for model in models:
                if (
                    model._meta.app == row[app_field]
                    and model._meta._model.__name__ == row[model_field]
                ):
                    row = {
                        field: row[field]
                        for field in row.keys()
                        if field not in [model_field, app_field]
                    }
                    instance_list.append(model._init_from_db(**row))
                    break

        return instance_list

    def _prepare_insert_columns(
        self, include_generated: bool = False
    ) -> tuple[list[str], list[str]]:
        regular_columns = []
        for column in self.model._meta.fields_db_projection.keys():
            field_object = self.model._meta.fields_map[column]
            if include_generated or not field_object.generated:
                regular_columns.append(column)
        result_columns = [self.model._meta.fields_db_projection[c] for c in regular_columns]
        return regular_columns, result_columns

    def _prepare_insert_statement(
        self, columns: Sequence[str], has_generated: bool = True, ignore_conflicts: bool = False
    ) -> QueryBuilder:
        # Insert should implement returning new id to saved object
        # Each db has its own methods for it, so each implementation should
        # go to descendant executors
        query = (
            self.db.query_class.into(self.model._meta.basetable)
            .columns(*columns)
            .insert(*[self.parameter(i) for i in range(len(columns))])
        )
        if ignore_conflicts:
            query = query.on_conflict().do_nothing()
        return query

    async def _process_insert_result(self, instance: Model, results: Any) -> None:
        raise NotImplementedError()  # pragma: nocoverage

    def parameter(self, pos: int) -> Parameter:
        return Parameter(idx=pos + 1)

    def _has_db_default_values(self, instance: Model, columns: list[str]) -> bool:
        """Check whether any column on the instance still holds a DatabaseDefault sentinel."""

        if not self.model._meta.db_default_db_columns:
            return False
        for field_name in columns:
            if isinstance(getattr(instance, field_name, None), DatabaseDefault):
                return True
        return False

    def _build_insert_with_defaults(
        self,
        instance: Model,
        columns: list[str] | None = None,
        has_generated: bool = True,
        ignore_conflicts: bool = False,
    ) -> tuple[str, list[Any], list[str]]:
        """Build an INSERT query where DatabaseDefault fields are omitted.

        Returns ``(sql_string, values_list, db_default_columns)`` where:
        - *values_list* only contains bind values for non-DatabaseDefault fields.
        - *db_default_columns* lists the DB column names that were omitted from
          the INSERT (they will use the DB-level DEFAULT).
        """

        if columns is None:
            columns = self.regular_columns

        active_db_columns: list[str] = []
        values: list[Any] = []
        db_default_columns: list[str] = []

        for field_name in columns:
            field_object = self.model._meta.fields_map[field_name]
            value = getattr(instance, field_name)
            db_col = self.model._meta.fields_db_projection[field_name]
            if isinstance(value, DatabaseDefault):
                db_default_columns.append(db_col)
            else:
                active_db_columns.append(db_col)
                values.append(field_object.to_db_value(value, instance))

        table = self.model._meta.basetable

        if active_db_columns:
            insert_terms = [self.parameter(i) for i in range(len(active_db_columns))]
            query = (
                self.db.query_class.into(table).columns(*active_db_columns).insert(*insert_terms)
            )
        else:
            query = self.db.query_class.into(table).default_values()

        query = self._add_returning_to_insert(query, has_generated, db_default_columns)
        if ignore_conflicts:
            query = query.on_conflict().do_nothing()
        return str(query), values, db_default_columns

    def _get_returning_fields(
        self,
        has_generated: bool,
        db_default_columns: list[str],
    ) -> list[str]:
        """Compute the list of column names for a RETURNING clause.

        Combines generated fields (when *has_generated* is True) with
        *db_default_columns*, deduplicating in order.
        """
        returning_fields: list[str] = []
        if has_generated and (generated_fields := self.model._meta.generated_db_fields):
            returning_fields.extend(generated_fields)
        for col in db_default_columns:
            if col not in returning_fields:
                returning_fields.append(col)
        return returning_fields

    def _add_returning_to_insert(
        self,
        query: QueryBuilder,
        has_generated: bool,
        db_default_columns: list[str],
    ) -> QueryBuilder:
        """Hook for backends to add RETURNING clause.

        Base implementation does nothing (backends without RETURNING support).
        Override in PostgreSQL and SQLite executors.
        """
        return query

    async def _execute_insert_dynamic(
        self,
        instance: Model,
        columns: list[str],
        has_generated: bool,
    ) -> Any:
        """Execute a dynamic INSERT (with DEFAULT keywords) and return the raw result.

        Calls ``_build_insert_with_defaults`` to produce the SQL, then
        executes it via the DB client.
        """
        query, values, _db_default_columns = self._build_insert_with_defaults(
            instance, columns=columns, has_generated=has_generated
        )
        return await self.db.execute_insert(query, values)

    async def execute_insert(self, instance: Model) -> None:
        if not instance._custom_generated_pk:
            has_db_defaults = self._has_db_default_values(instance, self.regular_columns)

            if has_db_defaults:
                insert_result = await self._execute_insert_dynamic(
                    instance, self.regular_columns, has_generated=True
                )
            else:
                values = [
                    self.model._meta.fields_map[field_name].to_db_value(
                        getattr(instance, field_name), instance
                    )
                    for field_name in self.regular_columns
                ]
                insert_result = await self.db.execute_insert(self.insert_query, values)
            await self._process_insert_result(instance, insert_result)

        else:
            has_db_defaults = self._has_db_default_values(instance, self.regular_columns_all)

            if has_db_defaults:
                insert_result = await self._execute_insert_dynamic(
                    instance, self.regular_columns_all, has_generated=False
                )
                await self._process_insert_result(instance, insert_result)
            else:
                values = [
                    self.model._meta.fields_map[field_name].to_db_value(
                        getattr(instance, field_name), instance
                    )
                    for field_name in self.regular_columns_all
                ]
                await self.db.execute_insert(self.insert_query_all, values)

    async def _fetch_db_defaults_after_insert(self, instance: Model) -> None:
        """Fetch DB-applied default values via SELECT after INSERT.

        Called only for non-RETURNING backends when db_default fields
        were set to DEFAULT in the INSERT.
        Guarded by Meta.fetch_db_defaults.
        """

        if not self.model._meta.fetch_db_defaults:
            return

        db_default_db_columns = self.model._meta.db_default_db_columns
        if not db_default_db_columns:
            return

        # Determine which fields still have DatabaseDefault (not populated by RETURNING)
        fields_to_fetch = []
        db_projection_reverse = self.model._meta.fields_db_projection_reverse
        for db_col in db_default_db_columns:
            model_field = db_projection_reverse.get(db_col, db_col)
            if isinstance(getattr(instance, model_field, None), DatabaseDefault):
                fields_to_fetch.append(db_col)

        if not fields_to_fetch:
            return

        # Need PK to SELECT
        if instance.pk is None:
            return

        # Build SELECT via pypika for proper quoting
        table = self.model._meta.basetable
        pk_col = self.model._meta.db_pk_column
        query = (
            self.db.query_class.from_(table)
            .select(*fields_to_fetch)
            .where(table[pk_col] == self.parameter(0))
        )
        pk_value = self.model._meta.pk.to_db_value(instance.pk, instance)
        _, rows = await self.db.execute_query(str(query), [pk_value])

        if rows:
            row = rows[0]
            for db_col in fields_to_fetch:
                model_field = db_projection_reverse.get(db_col, db_col)
                field_object = self.model._meta.fields_map[model_field]
                raw_value = row.get(db_col)
                setattr(instance, model_field, field_object.to_python_value(raw_value))

    def get_update_sql(
        self,
        update_fields: Iterable[str] | None,
        expressions: dict[str, Expression] | None,
    ) -> str:
        """
        Generates the SQL for updating a model depending on provided update_fields.
        Result is cached for performance.
        """
        key = ",".join(update_fields) if update_fields else ""
        if not expressions and key in self.update_cache:
            return self.update_cache[key]
        expressions = expressions or {}
        table = self.model._meta.basetable
        query = self.db.query_class.update(table)
        parameter_idx = 0
        for field in update_fields or self.model._meta.fields_db_projection.keys():
            db_column = self.model._meta.fields_db_projection[field]
            field_object = self.model._meta.fields_map[field]
            if field_object.generated:
                if update_fields:
                    raise OperationalError(f"Can't update generated field {field}")
                continue
            if not field_object.pk:
                if field not in expressions.keys():
                    query = query.set(db_column, self.parameter(parameter_idx))
                    parameter_idx += 1
                else:
                    value = (
                        expressions[field]
                        .resolve(
                            ResolveContext(
                                model=self.model,
                                table=table,
                                annotations={},
                                custom_filters={},
                            )
                        )
                        .term
                    )
                    query = query.set(db_column, value)

        query = query.where(table[self.model._meta.db_pk_column] == self.parameter(parameter_idx))

        sql = query.get_sql()
        if not expressions:
            self.update_cache[key] = sql
        return sql

    async def execute_update(
        self, instance: type[Model] | Model, update_fields: Iterable[str] | None
    ) -> int:

        user_specified = update_fields is not None
        source_fields: list[str] = (
            list(update_fields)
            if update_fields is not None
            else list(self.model._meta.fields_db_projection.keys())
        )

        effective_fields: list[str] = []
        for field in source_fields:
            field_obj = self.model._meta.fields_map[field]
            if field_obj.pk:
                if user_specified:
                    raise OperationalError(
                        f"Can't update pk field, use `{self.model.__name__}.create` instead."
                    )
                continue
            if field_obj.generated:
                if user_specified:
                    raise OperationalError(f"Can't update generated field {field}")
                continue
            instance_field = getattr(instance, field)
            if isinstance(instance_field, DatabaseDefault):
                continue
            effective_fields.append(field)

        if not effective_fields:
            return 0

        values = []
        expressions = {}
        for field in effective_fields:
            instance_field = getattr(instance, field)
            if isinstance(instance_field, Expression):
                expressions[field] = instance_field
            else:
                field_obj = self.model._meta.fields_map[field]
                values.append(field_obj.to_db_value(instance_field, instance))

        values.append(self.model._meta.pk.to_db_value(instance.pk, instance))
        return (
            await self.db.execute_query(self.get_update_sql(effective_fields, expressions), values)
        )[0]

    async def execute_delete(self, instance: type[Model] | Model) -> int:
        return (
            await self.db.execute_query(
                self.delete_query, [self.model._meta.pk.to_db_value(instance.pk, instance)]
            )
        )[0]

    async def _prefetch_reverse_relation(
        self,
        instance_list: Iterable[Model],
        field: str,
        related_query: tuple[str | None, QuerySet],
    ) -> Iterable[Model]:
        to_attr, related_query = related_query
        related_objects_for_fetch: dict[str, list] = {}
        related_field: BackwardFKRelation = self.model._meta.fields_map[field]  # type: ignore
        related_field_name = related_field.to_field_instance.model_field_name
        relation_field = related_field.relation_field

        for instance in instance_list:
            if relation_field not in related_objects_for_fetch:
                related_objects_for_fetch[relation_field] = []
            related_objects_for_fetch[relation_field].append(
                instance._meta.fields_map[related_field_name].to_db_value(
                    getattr(instance, related_field_name), instance
                )
            )

        related_query.resolve_ordering(
            related_query.model, related_query.model._meta.basetable, [], {}
        )
        related_object_queryset = related_query.filter(
            **{f"{k}__in": v for k, v in related_objects_for_fetch.items()}
        )
        if related_object_queryset._db is not self.db:
            related_object_queryset._db = self.db
        related_object_list = await related_object_queryset

        related_object_map: dict[str, list] = {}
        for entry in related_object_list:
            object_id = getattr(entry, relation_field)
            if object_id in related_object_map:
                related_object_map[object_id].append(entry)
            else:
                related_object_map[object_id] = [entry]
        for instance in instance_list:
            relation_container = getattr(instance, field)
            relation_container._set_result_for_query(
                related_object_map.get(getattr(instance, related_field_name), []),
                to_attr,
            )
        return instance_list

    async def _prefetch_reverse_o2o_relation(
        self,
        instance_list: Iterable[Model],
        field: str,
        related_query: tuple[str | None, QuerySet],
    ) -> Iterable[Model]:
        to_attr, related_query = related_query
        related_objects_for_fetch: dict[str, list] = {}
        related_field: BackwardOneToOneRelation = self.model._meta.fields_map[field]  # type: ignore
        related_field_name = related_field.to_field_instance.model_field_name
        relation_field = related_field.relation_field

        for instance in instance_list:
            if relation_field not in related_objects_for_fetch:
                related_objects_for_fetch[relation_field] = []
            related_objects_for_fetch[relation_field].append(
                instance._meta.fields_map[related_field_name].to_db_value(
                    getattr(instance, related_field_name), instance
                )
            )

        related_object_queryset = related_query.filter(
            **{f"{k}__in": v for k, v in related_objects_for_fetch.items()}
        )
        if related_object_queryset._db is not self.db:
            related_object_queryset._db = self.db
        related_object_list = await related_object_queryset

        related_object_map = {}
        for entry in related_object_list:
            object_id = getattr(entry, relation_field)
            related_object_map[object_id] = entry

        for instance in instance_list:
            obj = related_object_map.get(getattr(instance, related_field_name), None)
            setattr(
                instance,
                f"_{field}",
                obj,
            )
            if to_attr:
                setattr(instance, to_attr, obj)
        return instance_list

    async def _prefetch_m2m_relation(
        self,
        instance_list: Iterable[Model],
        field: str,
        related_query: tuple[str | None, QuerySet],
    ) -> Iterable[Model]:
        to_attr, related_query = related_query
        instance_id_set: set = {
            instance._meta.pk.to_db_value(instance.pk, instance) for instance in instance_list
        }

        field_object: ManyToManyFieldInstance = self.model._meta.fields_map[field]  # type: ignore

        through_table = Table(field_object.through, schema=field_object.through_schema)

        subquery = (
            self.db.query_class.from_(through_table)
            .select(
                through_table[field_object.backward_key].as_("_backward_relation_key"),
                through_table[field_object.forward_key].as_("_forward_relation_key"),
            )
            .where(through_table[field_object.backward_key].isin(instance_id_set))
        )

        related_query_table = related_query.model._meta.basetable
        related_pk_field = related_query.model._meta.db_pk_column
        related_query.resolve_ordering(related_query.model, related_query_table, [], {})
        query = (
            related_query.query.join(subquery)
            .on(subquery._forward_relation_key == related_query_table[related_pk_field])
            .select(
                subquery._backward_relation_key.as_("_backward_relation_key"),
                *[related_query_table[field].as_(field) for field in related_query.fields],
            )
        )

        if related_query._q_objects:
            joined_tables: list[Table] = []
            modifier = QueryModifier()
            for node in related_query._q_objects:
                modifier &= node.resolve(
                    ResolveContext(
                        model=related_query.model,
                        table=related_query_table,
                        annotations=related_query._annotations,
                        custom_filters=related_query._custom_filters,
                    )
                )

            for join in modifier.joins:
                if join[0] not in joined_tables:
                    query = query.join(join[0], how=JoinType.left_outer).on(join[1])
                    joined_tables.append(join[0])

            if modifier.where_criterion:
                query = query.where(modifier.where_criterion)

            if modifier.having_criterion:
                query = query.having(modifier.having_criterion)

        _, raw_results = await self.db.execute_query(*query.get_parameterized_sql())
        relations: list[tuple[Any, Any]] = []
        related_object_list: list[Model] = []
        model_pk, related_pk = self.model._meta.pk, field_object.related_model._meta.pk
        for e in raw_results:
            pk_values: tuple[Any, Any] = (
                model_pk.to_python_value(e["_backward_relation_key"]),
                related_pk.to_python_value(e[related_pk_field]),
            )
            relations.append(pk_values)
            related_object_list.append(related_query.model._init_from_db(**e))
        await self.__class__(
            model=related_query.model, db=self.db, prefetch_map=related_query._prefetch_map
        )._execute_prefetch_queries(related_object_list)
        related_object_map = {e.pk: e for e in related_object_list}
        relation_map: dict[str, list] = {}

        for object_id, related_object_id in relations:
            if object_id not in relation_map:
                relation_map[object_id] = []
            relation_map[object_id].append(related_object_map[related_object_id])

        for instance in instance_list:
            relation_container = getattr(instance, field)
            relation_container._set_result_for_query(relation_map.get(instance.pk, []), to_attr)
        return instance_list

    async def _prefetch_direct_relation(
        self,
        instance_list: Iterable[Model],
        field: str,
        related_query: tuple[str | None, QuerySet],
    ) -> Iterable[Model]:
        to_attr, related_queryset = related_query
        related_objects_for_fetch: dict[str, list] = {}
        relation_key_field = f"{field}_id"
        model_to_field: dict[type[Model], str] = {}
        for instance in instance_list:
            if (value := getattr(instance, relation_key_field)) is not None:
                if (model_cls := instance.__class__) in model_to_field:
                    key = model_to_field[model_cls]
                else:
                    related_field = cast(RelationalField, instance._meta.fields_map[field])
                    model_to_field[model_cls] = key = related_field.to_field
                    if key not in related_objects_for_fetch:
                        related_objects_for_fetch[key] = []
                if value not in (values := related_objects_for_fetch[key]):
                    values.append(value)
            else:
                setattr(instance, field, None)

        if related_objects_for_fetch:
            conditions: dict[str, Any] = {}
            for k, v in related_objects_for_fetch.items():
                if len(v) == 1:
                    v = v[0]
                else:
                    k += "__in"
                conditions[k] = v
            related_object_queryset = related_queryset.filter(**conditions)
            # ``.filter`` clones the queryset and may revert ``_db`` to the
            # one configured on a user-supplied Prefetch queryset; rebind it
            # so the query uses the held streaming/transaction connection.
            if related_object_queryset._db is not self.db:
                related_object_queryset._db = self.db
            related_object_list = await related_object_queryset
            if len(model_to_field) > 1:
                related_object_map = {
                    getattr(obj, model_to_field[obj.__class__]): obj for obj in related_object_list
                }
            else:
                related_object_map = {getattr(obj, key): obj for obj in related_object_list}
            for instance in instance_list:
                obj = related_object_map.get(getattr(instance, relation_key_field))
                setattr(instance, field, obj)
                if to_attr:
                    setattr(instance, to_attr, obj)
        return instance_list

    def _make_prefetch_queries(self) -> None:
        for field_name, forwarded_prefetches in self.prefetch_map.items():
            to_attr = None
            if field_name in self._prefetch_queries:
                to_attr, related_query = self._prefetch_queries[field_name][0]
            else:
                relation_field = self.model._meta.fields_map[field_name]
                related_model: type[Model] = relation_field.related_model  # type: ignore
                related_query = related_model.all().using_db(self.db)
                related_query.query = copy(  # type:ignore[assignment]
                    related_query.model._meta.basequery
                )
            if forwarded_prefetches:
                related_query = related_query.prefetch_related(*forwarded_prefetches)
            # Prefetch queries must run on the same connection the streaming
            # cursor is holding (or inside the current transaction), otherwise
            # they would block on the stream's unreleased connection/lock.
            if related_query._db is not self.db:
                related_query._db = self.db
            self._prefetch_queries.setdefault(field_name, []).append((to_attr, related_query))

    async def _do_prefetch(
        self,
        instance_id_list: Iterable[Model],
        field: str,
        related_query: tuple[str | None, QuerySet],
    ) -> Iterable[Model]:
        if field in self.model._meta.backward_fk_fields:
            return await self._prefetch_reverse_relation(instance_id_list, field, related_query)

        if field in self.model._meta.backward_o2o_fields:
            return await self._prefetch_reverse_o2o_relation(instance_id_list, field, related_query)

        if field in self.model._meta.m2m_fields:
            return await self._prefetch_m2m_relation(instance_id_list, field, related_query)
        return await self._prefetch_direct_relation(instance_id_list, field, related_query)

    async def _execute_prefetch_queries(self, instance_list: Iterable[Model]) -> Iterable[Model]:
        if instance_list and (self.prefetch_map or self._prefetch_queries):
            self._make_prefetch_queries()
            prefetch_tasks = []
            for field, related_queries in self._prefetch_queries.items():
                for related_query in related_queries:
                    prefetch_tasks.append(self._do_prefetch(instance_list, field, related_query))
            await asyncio.gather(*prefetch_tasks)

        return instance_list

    async def fetch_for_list(self, instance_list: Iterable[Model], *args: str) -> Iterable[Model]:
        self.prefetch_map = {}
        for relation in args:
            first_level_field, __, forwarded_prefetch = relation.partition("__")
            if first_level_field not in self.model._meta.fetch_fields:
                raise OperationalError(
                    f"relation {first_level_field} for {self.model._meta.db_table} not found"
                )

            if first_level_field not in self.prefetch_map.keys():
                self.prefetch_map[first_level_field] = set()

            if forwarded_prefetch:
                self.prefetch_map[first_level_field].add(forwarded_prefetch)

        await self._execute_prefetch_queries(instance_list)
        return instance_list

    @classmethod
    def get_overridden_filter_func(
        cls, filter_func: Callable, filter_info: FilterInfoDict | None = None
    ) -> Callable | None:
        return cls.FILTER_FUNC_OVERRIDE.get(filter_func)


class _ModelBatchStream:
    """Stateful model-instance batch source backed by an open streaming cursor.

    The cursor (and its connection/pool slot/transaction lock) is opened on the
    first batch and released synchronously by :meth:`aclose`, which is
    triggered by ``StreamingResult`` on break/cancellation/error.
    """

    __slots__ = (
        "_owner",
        "_sql",
        "_values",
        "_custom_fields",
        "_batch_size",
        "_context",
        "_cursor",
        "_executor",
        "_closed",
    )

    def __init__(self, owner: BaseExecutor, sql, values, custom_fields, batch_size) -> None:
        self._owner = owner
        self._sql = sql
        self._values = values
        self._custom_fields = custom_fields
        self._batch_size = batch_size
        self._context = None
        self._cursor = None
        self._executor: BaseExecutor | None = None
        self._closed = False

    async def fetch_batch(self) -> list:
        if self._cursor is None:
            self._context = self._owner.db.execute_query_stream(self._sql, self._values)
            self._cursor = await self._context.__aenter__()
            self._executor = self._owner.__class__(
                model=self._owner.model,
                db=self._cursor.sibling_client,
                prefetch_map=self._owner.prefetch_map,
                prefetch_queries=self._owner._prefetch_queries,
                select_related_idx=self._owner.select_related_idx,
            )
        raw_rows = await self._cursor.fetchmany(self._batch_size)
        if not raw_rows:
            return []
        await asyncio.sleep(0)
        assert self._executor is not None
        instance_list = await self._executor._instances_from_rows(
            list(raw_rows), self._custom_fields
        )
        await self._executor._execute_prefetch_queries(instance_list)
        return instance_list

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        cursor = self._cursor
        if cursor is not None:
            try:
                await cursor.aclose()
            finally:
                self._cursor = None
                self._context = None
