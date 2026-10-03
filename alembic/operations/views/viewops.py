from __future__ import annotations

from typing import Any
from typing import TYPE_CHECKING

from ...operations.base import Operations
from ...operations.ops import MigrateOperation
from . import base as _base

if TYPE_CHECKING:
    from sqlalchemy.sql.elements import quoted_name
    from sqlalchemy.sql.selectable import SelectBase


@Operations.register_operation("create_view")
class CreateViewOp(MigrateOperation):
    """Represent a ``CREATE VIEW`` operation."""

    def __init__(
        self,
        view_name: str | quoted_name,
        definition: str | SelectBase,
        *,
        schema: str | quoted_name | None = None,
        or_replace: bool = False,
        materialized: bool = False,
    ) -> None:
        self.view_name = view_name
        self.definition = definition
        self.schema = schema
        self.or_replace = or_replace
        self.materialized = materialized

    def reverse(self) -> DropViewOp:
        return DropViewOp(
            self.view_name,
            schema=self.schema,
            materialized=self.materialized,
        )

    def to_diff_tuple(self) -> tuple[str, Any]:
        return (
            "add_view",
            (str(self.schema), str(self.view_name)),
            self.definition,
        )

    @classmethod
    def from_view(cls, view: _base.View) -> CreateViewOp:
        return cls(
            view.name,
            view.definition,
            schema=view.schema,
            materialized=view.materialized,
        )

    @classmethod
    def create_view(
        cls,
        operations: Operations,
        view_name: str | quoted_name,
        definition: str | SelectBase,
        *,
        schema: str | quoted_name | None = None,
        or_replace: bool = False,
        materialized: bool = False,
    ) -> None:
        """Issue a CREATE VIEW instruction.

        e.g.::

            op.create_view(
                "active_users",
                "SELECT id, name FROM users WHERE status = 'active'",
            )

        :param view_name: name of the view; may be a
         :class:`.quoted_name` to force quoting.
        :param definition: the SELECT body, either a SQL string (a bare
         SELECT or a full CREATE VIEW statement) or a SQLAlchemy
         :class:`.SelectBase` construct.
        :param schema: optional schema name, also :class:`.quoted_name`.
        :param or_replace: emit CREATE OR REPLACE where the dialect
         supports it. Defaults to False for portability (SQLite does not
         support OR REPLACE).
        :param materialized: create a MATERIALIZED VIEW.
        """

        operations.invoke(
            cls(
                view_name,
                definition,
                schema=schema,
                or_replace=or_replace,
                materialized=materialized,
            )
        )


@Operations.register_operation("drop_view")
class DropViewOp(MigrateOperation):
    """Represent a ``DROP VIEW`` operation.

    When *definition* is provided (as autogenerate always does), the
    operation is reversible and its downgrade recreates the view with the
    given definition.
    """

    def __init__(
        self,
        view_name: str | quoted_name,
        *,
        schema: str | quoted_name | None = None,
        if_exists: bool = False,
        cascade: bool = False,
        materialized: bool = False,
        definition: str | SelectBase | None = None,
    ) -> None:
        self.view_name = view_name
        self.schema = schema
        self.if_exists = if_exists
        self.cascade = cascade
        self.materialized = materialized
        self.definition = definition

    def reverse(self) -> MigrateOperation:
        if self.definition is None:
            raise NotImplementedError(
                "drop_view() without a definition is not reversible; "
                "pass definition= so the downgrade can recreate the view"
            )
        return CreateViewOp(
            self.view_name,
            self.definition,
            schema=self.schema,
            materialized=self.materialized,
        )

    def to_diff_tuple(self) -> tuple[str, Any]:
        return (
            "remove_view",
            (str(self.schema), str(self.view_name)),
        )

    @classmethod
    def drop_view(
        cls,
        operations: Operations,
        view_name: str | quoted_name,
        *,
        schema: str | quoted_name | None = None,
        if_exists: bool = False,
        cascade: bool = False,
        materialized: bool = False,
        definition: str | SelectBase | None = None,
    ) -> None:
        """Issue a DROP VIEW instruction.

        :param view_name: name of the view; may be :class:`.quoted_name`.
        :param schema: optional schema name.
        :param if_exists: emit IF EXISTS.
        :param cascade: emit CASCADE (databases that support it).
        :param materialized: drop a MATERIALIZED VIEW.
        :param definition: optional current SELECT body of the view, used
         to make the operation reversible (downgrade recreates it).
        """

        operations.invoke(
            cls(
                view_name,
                schema=schema,
                if_exists=if_exists,
                cascade=cascade,
                materialized=materialized,
                definition=definition,
            )
        )


@Operations.register_operation("replace_view")
class ReplaceViewOp(MigrateOperation):
    """Represent a portable replace of a view definition.

    Implemented as DROP VIEW followed by CREATE VIEW so it works on SQLite
    as well as on databases that provide CREATE OR REPLACE. When other
    views depend on the view, the caller must tear down and recreate the
    dependents in the right order; autogenerate emits that plan
    explicitly.
    """

    def __init__(
        self,
        view_name: str | quoted_name,
        new_definition: str | SelectBase,
        *,
        old_definition: str | SelectBase | None = None,
        schema: str | quoted_name | None = None,
        materialized: bool = False,
    ) -> None:
        self.view_name = view_name
        self.new_definition = new_definition
        self.old_definition = old_definition
        self.schema = schema
        self.materialized = materialized

    def reverse(self) -> ReplaceViewOp:
        if self.old_definition is None:
            raise NotImplementedError(
                "replace_view() requires old_definition to be reversible"
            )
        return ReplaceViewOp(
            self.view_name,
            self.old_definition,
            old_definition=self.new_definition,
            schema=self.schema,
            materialized=self.materialized,
        )

    def to_diff_tuple(self) -> tuple[str, Any]:
        return (
            "replace_view",
            (str(self.schema), str(self.view_name)),
            self.old_definition,
            self.new_definition,
        )

    @classmethod
    def replace_view(
        cls,
        operations: Operations,
        view_name: str | quoted_name,
        new_definition: str | SelectBase,
        *,
        old_definition: str | SelectBase | None = None,
        schema: str | quoted_name | None = None,
        materialized: bool = False,
    ) -> None:
        """Replace an existing view definition portably.

        Emits DROP VIEW then CREATE VIEW, so it works on SQLite as well
        as on databases that support CREATE OR REPLACE. Pass
        *old_definition* to make the operation reversible.
        """

        operations.invoke(
            cls(
                view_name,
                new_definition,
                old_definition=old_definition,
                schema=schema,
                materialized=materialized,
            )
        )


@Operations.implementation_for(CreateViewOp)
def _create_view(operations: Operations, operation: CreateViewOp) -> None:
    dialect = operations.impl.dialect
    operations.impl.execute(
        _base.create_view_sql(
            operation.view_name,
            operation.definition,
            dialect,
            schema=operation.schema,
            or_replace=operation.or_replace,
            materialized=operation.materialized,
        )
    )


@Operations.implementation_for(DropViewOp)
def _drop_view(operations: Operations, operation: DropViewOp) -> None:
    dialect = operations.impl.dialect
    operations.impl.execute(
        _base.drop_view_sql(
            operation.view_name,
            dialect,
            schema=operation.schema,
            if_exists=operation.if_exists,
            cascade=operation.cascade,
            materialized=operation.materialized,
        )
    )


@Operations.implementation_for(ReplaceViewOp)
def _replace_view(operations: Operations, operation: ReplaceViewOp) -> None:
    operations.invoke(
        DropViewOp(
            operation.view_name,
            schema=operation.schema,
            materialized=operation.materialized,
        )
    )
    operations.invoke(
        CreateViewOp(
            operation.view_name,
            operation.new_definition,
            schema=operation.schema,
            materialized=operation.materialized,
        )
    )
