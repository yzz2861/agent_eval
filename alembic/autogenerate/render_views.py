# mypy: allow-untyped-defs, allow-incomplete-defs, allow-untyped-calls

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy.sql.elements import quoted_name
from sqlalchemy.sql.selectable import SelectBase

from ..operations.views import base as _view_base
from ..operations.views.viewops import CreateViewOp
from ..operations.views.viewops import DropViewOp
from ..operations.views.viewops import ReplaceViewOp
from . import render

if TYPE_CHECKING:
    from ..autogenerate.api import AutogenContext


def _render_view_name(value, autogen_context):
    if isinstance(value, quoted_name) and value.quote is True:
        prefix = render._sqlalchemy_autogenerate_prefix(autogen_context)
        return prefix + "quoted_name(" + repr(str(value)) + ", True)"
    return repr(str(value))


def _render_definition(definition, autogen_context):
    if isinstance(definition, str):
        return repr(_view_base._select_body(definition.strip()))
    if isinstance(definition, SelectBase):
        dialect = autogen_context.migration_context.impl.dialect
        return repr(_view_base.definition_sql(definition, dialect))
    return repr(str(definition))


@render.renderers.dispatch_for(CreateViewOp)
def _render_create_view(
    autogen_context: AutogenContext, op: CreateViewOp
) -> str:
    prefix = render._alembic_autogenerate_prefix(autogen_context)
    lines = [
        prefix + "create_view(",
        "    " + _render_view_name(op.view_name, autogen_context) + ",",
        "    " + _render_definition(op.definition, autogen_context) + ",",
    ]
    if op.schema is not None:
        lines.append(
            "    schema=" + _render_view_name(op.schema, autogen_context) + ","
        )
    if op.materialized:
        lines.append("    materialized=True,")
    if op.or_replace:
        lines.append("    or_replace=True,")
    lines.append(")")
    return "\n".join(lines)


@render.renderers.dispatch_for(DropViewOp)
def _render_drop_view(autogen_context: AutogenContext, op: DropViewOp) -> str:
    prefix = render._alembic_autogenerate_prefix(autogen_context)
    head = (
        prefix
        + "drop_view("
        + _render_view_name(op.view_name, autogen_context)
    )
    kwargs = []
    if op.schema is not None:
        kwargs.append(
            "schema=" + _render_view_name(op.schema, autogen_context)
        )
    if op.materialized:
        kwargs.append("materialized=True")
    if op.if_exists:
        kwargs.append("if_exists=True")
    if op.cascade:
        kwargs.append("cascade=True")
    if op.definition is not None:
        kwargs.append(
            "definition=" + _render_definition(op.definition, autogen_context)
        )
    if kwargs:
        return head + ", " + ", ".join(kwargs) + ")"
    return head + ")"


@render.renderers.dispatch_for(ReplaceViewOp)
def _render_replace_view(autogen_context, op):
    prefix = render._alembic_autogenerate_prefix(autogen_context)
    lines = [
        prefix + "replace_view(",
        "    " + _render_view_name(op.view_name, autogen_context) + ",",
        "    " + _render_definition(op.new_definition, autogen_context) + ",",
    ]
    if op.old_definition is not None:
        lines.append(
            "    old_definition="
            + _render_definition(op.old_definition, autogen_context)
            + ","
        )
    if op.schema is not None:
        lines.append(
            "    schema=" + _render_view_name(op.schema, autogen_context) + ","
        )
    if op.materialized:
        lines.append("    materialized=True,")
    lines.append(")")
    return "\n".join(lines)
