# mypy: allow-untyped-calls, allow-untyped-defs

from __future__ import annotations

import logging

from ...operations import ops
from ...util import PriorityDispatchResult
from ...views import _strip_create_view_prefix
from ...views import CircularViewDependencyError
from ...views import closure
from ...views import declared_views
from ...views import definitions_equal
from ...views import reverse_topological_sort
from ...views import topological_sort
from ...views import view_definition_text

log = logging.getLogger(__name__)

_PLAN_ATTR = "_alembic_view_plan"


def _reflected_views(autogen_context, schemas):
    """Return {key: (view_object_like, definition_sql)} from database."""

    inspector = autogen_context.inspector
    reflected = {}
    for schema_name in schemas:
        try:
            view_names = inspector.get_view_names(schema=schema_name)
        except NotImplementedError:
            log.info(
                "dialect %r does not support view reflection; skipping "
                "view comparison" % (autogen_context.dialect.name,),
            )
            return None

        for view_name in view_names:
            if not autogen_context.run_name_filters(
                view_name, "view", {"schema_name": schema_name}
            ):
                continue
            definition = inspector.get_view_definition(
                view_name, schema=schema_name
            )
            reflected[(schema_name, view_name)] = definition
    return reflected


def _normalize_schema(autogen_context, key):
    schema, name = key
    default_schema = autogen_context.dialect.default_schema_name
    if schema == default_schema:
        schema = None
    return schema, name


def _build_view_plan(autogen_context, upgrade_ops, schemas):
    """Compute the global drop/create plan for views.

    Returns a tuple ``(drop_ops, create_ops)``.  The plan is cached on
    the upgrade ops container; the FIRST-priority comparator appends the
    drops, the LAST-priority comparator appends the creates.
    """

    if getattr(upgrade_ops, _PLAN_ATTR, None) is not None:
        return getattr(upgrade_ops, _PLAN_ATTR)

    if not autogen_context.opts.get("compare_views", True):
        plan = ([], [])
        setattr(upgrade_ops, _PLAN_ATTR, plan)
        return plan

    dialect = autogen_context.dialect
    declared = {
        _normalize_schema(autogen_context, key): view
        for key, view in declared_views(autogen_context.metadata).items()
    }

    reflected_raw = _reflected_views(autogen_context, schemas)
    if reflected_raw is None:
        plan = ([], [])
        setattr(upgrade_ops, _PLAN_ATTR, plan)
        return plan
    reflected = {
        _normalize_schema(autogen_context, key): sql
        for key, sql in reflected_raw.items()
    }

    declared_keys = set(declared)
    reflected_keys = set(reflected)

    def _declared_included(key):
        return autogen_context.run_object_filters(
            declared[key], key[1], "view", False, reflected.get(key)
        )

    def _reflected_included(key):
        return autogen_context.run_object_filters(
            _ReflectedView(key, reflected[key]), key[1], "view", True, None
        )

    added = {
        key
        for key in (declared_keys - reflected_keys)
        if _declared_included(key)
    }
    removed = {
        key
        for key in (reflected_keys - declared_keys)
        if _reflected_included(key)
    }
    existing = {
        key
        for key in (declared_keys & reflected_keys)
        if _declared_included(key) and _reflected_included(key)
    }

    changed = set()
    for key in existing:
        view = declared[key]
        if not autogen_context.run_object_filters(
            view, key[1], "view", False, reflected[key]
        ):
            continue
        new_sql = view_definition_text(view.selectable, dialect=dialect)
        if not definitions_equal(new_sql, reflected[key]):
            changed.add(key)

    # dependency edges restricted to the set of views known on each side
    new_deps = {
        key: (declared[key].dependencies(dialect) & declared_keys)
        for key in declared
    }
    old_deps = {
        key: (
            _infer_dependencies(autogen_context, key, reflected)
            & reflected_keys
        )
        for key in reflected
    }

    # views that must be dropped: removed views, changed views, and
    # existing views that (transitively) depend on a changed view
    dependents = _invert(old_deps)
    rebuilt = closure(changed, dependents) if changed else set()
    drop_keys = removed | rebuilt

    try:
        drop_order = reverse_topological_sort(drop_keys, old_deps)
    except CircularViewDependencyError:
        # a cycle in the *existing* database blocks a safe plan
        raise

    # views that must be created: added views plus everything rebuilt
    create_keys = added | rebuilt
    try:
        create_order = topological_sort(create_keys, new_deps)
    except CircularViewDependencyError:
        raise

    drop_ops = []
    for key in drop_order:
        if key in removed:
            if not autogen_context.run_object_filters(
                _ReflectedView(key, reflected[key]), key[1], "view", True, None
            ):
                continue
            drop_ops.append(
                ops.DropViewOp(
                    key[1],
                    schema=key[0],
                    old_view_sql=None,
                )
            )
            log.info("Detected removed view %r", key)
        else:
            view = declared[key]
            drop_ops.append(
                ops.DropViewOp(
                    view.name,
                    schema=view.schema,
                    materialized=view.materialized,
                    old_view_sql=_strip_create_view_prefix(reflected[key]),
                    old_temporary=view.temporary,
                    old_depends_on=sorted(view.dependencies(dialect)),
                    _as_replace=key in changed,
                    _view=view,
                )
            )

    create_ops = []
    for key in create_order:
        view = declared[key]
        create_ops.append(ops.CreateViewOp.from_view(view, dialect=dialect))
        if key in added:
            log.info("Detected added view %r", key)
        else:
            log.info("Detected changed view %r", key)

    plan = (drop_ops, create_ops)
    setattr(upgrade_ops, _PLAN_ATTR, plan)
    return plan


class _ReflectedView:
    """Minimal object representing a reflected view for filters."""

    __slots__ = ("name", "schema", "selectable")

    def __init__(self, key, definition):
        self.schema, self.name = key
        self.selectable = definition

    @property
    def key(self):
        return self.schema, self.name


def _invert(edges):
    inverted = {}
    for node, deps in edges.items():
        for dep in deps:
            inverted.setdefault(dep, set()).add(node)
    return inverted


def _infer_dependencies(autogen_context, key, reflected):
    from ...views import _strip_create_view_prefix
    from ...views import view_dependencies

    schema, _name = key
    body = _strip_create_view_prefix(reflected[key])
    return {dep for dep in view_dependencies(body, schema=schema)}


def _autogen_drop_views(
    autogen_context,
    upgrade_ops,
    schemas,
):
    drop_ops, _ = _build_view_plan(autogen_context, upgrade_ops, schemas)
    upgrade_ops.ops[0:0] = drop_ops
    return PriorityDispatchResult.CONTINUE


def _autogen_create_views(
    autogen_context,
    upgrade_ops,
    schemas,
):
    _, create_ops = _build_view_plan(autogen_context, upgrade_ops, schemas)
    upgrade_ops.ops.extend(create_ops)
    return PriorityDispatchResult.CONTINUE


def setup(plugin):
    from ...util import DispatchPriority

    plugin.add_autogenerate_comparator(
        _autogen_drop_views,
        "schema",
        "views_drop",
        priority=DispatchPriority.FIRST,
    )
    plugin.add_autogenerate_comparator(
        _autogen_create_views,
        "schema",
        "views_create",
        priority=DispatchPriority.LAST,
    )
