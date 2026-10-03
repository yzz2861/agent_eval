# mypy: allow-untyped-defs, allow-untyped-calls, allow-incomplete-defs

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ...operations.views import View
from ...operations.views import ViewRegistry
from ...operations.views import base as _view_base
from ...operations.views import definitions_equal
from ...operations.views import topological_order
from ...operations.views import view_dependency_edges
from ...operations.views.viewops import CreateViewOp
from ...operations.views.viewops import DropViewOp
from ...util import PriorityDispatchResult

if TYPE_CHECKING:
    from ...autogenerate.api import AutogenContext
    from ...operations.ops import UpgradeOps
    from ...operations.views.base import ViewKey
    from ...runtime.plugins import Plugin

log = logging.getLogger(__name__)


def _iter_metadatas(autogen_context: AutogenContext):
    metadatas = autogen_context.metadata
    if metadatas is None:
        return ()
    if isinstance(metadatas, (list, tuple)):
        return tuple(metadatas)
    return (metadatas,)


def _collect_target_views(
    autogen_context: AutogenContext, schemas: set[str | None]
) -> dict[ViewKey, View]:
    by_key: dict[ViewKey, View] = {}

    def absorb(registry: ViewRegistry | None) -> None:
        if registry is None:
            return
        for view in registry:
            if view.key[0] in schemas and view.key not in by_key:
                by_key[view.key] = view

    absorb(ViewRegistry.coerce(autogen_context.opts.get("target_views")))
    for metadata in _iter_metadatas(autogen_context):
        absorb(ViewRegistry.coerce(metadata.info.get("views")))
    return by_key


def _reflected_views(
    autogen_context: AutogenContext, schemas: set[str | None]
) -> dict[ViewKey, str]:
    inspector = autogen_context.inspector
    reflected: dict[ViewKey, str] = {}
    for schema in schemas:
        try:
            names = inspector.get_view_names(schema=schema)
        except NotImplementedError:
            continue
        for name in names:
            if not autogen_context.run_name_filters(
                name, "view", {"schema_name": schema}
            ):
                continue
            if not autogen_context.run_object_filters(
                None, name, "view", True, None
            ):
                continue
            definition = inspector.get_view_definition(name, schema=schema)
            reflected[(schema, name)] = definition or ""
    return reflected


def _transitive_dependents(
    seed: set[ViewKey], dependents_of: dict[ViewKey, set[ViewKey]]
) -> set[ViewKey]:
    result: set[ViewKey] = set()
    stack = list(seed)
    while stack:
        node = stack.pop()
        if node in result:
            continue
        result.add(node)
        for dependent in dependents_of.get(node, ()):
            if dependent not in result:
                stack.append(dependent)
    return result


def _autogen_for_views(
    autogen_context: AutogenContext,
    upgrade_ops: UpgradeOps,
    schemas: set[str | None],
) -> PriorityDispatchResult:
    target = _collect_target_views(autogen_context, schemas)
    target = {
        key: view
        for key, view in target.items()
        if autogen_context.run_object_filters(
            None, str(view.name), "view", False, None
        )
    }
    reflected = _reflected_views(autogen_context, schemas)

    default_schema = autogen_context.dialect.default_schema_name

    target_keys = set(target)
    reflected_keys = set(reflected)

    # ---- changed detection (string definitions only) -------------------
    changed: set[ViewKey] = set()
    for key in target_keys & reflected_keys:
        new = target[key].definition
        if isinstance(new, str) and not definitions_equal(new, reflected[key]):
            changed.add(key)

    added = target_keys - reflected_keys
    removed = reflected_keys - target_keys

    # ---- dependency graphs ---------------------------------------------
    # target graph (declared definitions)
    target_edges = view_dependency_edges(list(target.values()), default_schema)
    # reflected graph (definitions as currently stored in the database)
    reflected_view_objs = [
        View(key[1], reflected[key], schema=key[0]) for key in reflected_keys
    ]
    reflected_edges = view_dependency_edges(
        reflected_view_objs, default_schema
    )
    dependents_of: dict[ViewKey, set[ViewKey]] = {
        key: set() for key in reflected_keys | target_keys
    }
    for node, deps in reflected_edges.items():
        for dep in deps:
            dependents_of.setdefault(dep, set()).add(node)

    # cycle detection on both graphs; errors report the involved views
    topological_order(target_edges)
    # reverse the reflected graph so dependency-first there is
    # dependents-first here, and surfaces any cycle
    reverse_reflected: dict[ViewKey, set[ViewKey]] = {
        key: set() for key in reflected_keys
    }
    for node, deps in reflected_edges.items():
        for dep in deps:
            reverse_reflected.setdefault(dep, set()).add(node)
    topological_order(reverse_reflected)

    # ---- tear down phase -----------------------------------------------
    # every changed view plus every view (recursively) depending on a
    # changed view must be dropped first. Removed views are also dropped
    # in dependents-first order.
    cascade = _transitive_dependents(changed, dependents_of)
    to_drop = cascade | removed
    # dependents-first order across the reflected views
    drop_order_all = topological_order(reverse_reflected)
    drops = [key for key in drop_order_all if key in to_drop]

    # ---- build phase ---------------------------------------------------
    # recreate everything dropped that still exists in the target: new
    # definition for added/changed views, otherwise the *current* reflected
    # definition for unchanged dependents that merely had to be rebuilt.
    rebuild_views: dict[ViewKey, View] = {}
    for key in drops:
        if key in removed:
            continue
        if key in target:
            rebuild_views[key] = target[key]
        else:
            rebuild_views[key] = View(
                key[1],
                _view_base._select_body(reflected[key].strip()),
                schema=key[0],
            )
    for key in added:
        rebuild_views[key] = target[key]
    rebuild_edges = view_dependency_edges(
        list(rebuild_views.values()), default_schema
    )
    creates = topological_order(rebuild_edges)

    # ---- emit primitive, reviewable ops --------------------------------
    # View drops are inserted at the *front* of the operation stream and
    # creates at the *end*.  This guarantees that, when an underlying table
    # is also altered in the same revision (e.g. SQLite batch recreate),
    # the views are gone before the table is touched and only rebuilt once
    # the new table shape is in place.
    drop_ops: list = []
    for key in drops:
        schema, name = key
        # carry the current definition so the reverse op recreates the
        # view exactly during downgrade
        old_definition = reflected.get(key)
        if old_definition is not None:
            old_definition = _view_base._select_body(old_definition.strip())
        drop_ops.append(
            DropViewOp(
                name,
                schema=schema,
                definition=old_definition,
                materialized=(
                    target[key].materialized if key in target else False
                ),
            )
        )
    upgrade_ops.ops[0:0] = drop_ops

    for key in creates:
        view = rebuild_views[key]
        upgrade_ops.ops.append(
            CreateViewOp(
                view.name,
                view.definition,
                schema=view.schema,
                materialized=view.materialized,
            )
        )

    if drops or creates:
        log.info(
            "Detected %d view drop(s) and %d view create(s)",
            len(drops),
            len(creates),
        )

    return PriorityDispatchResult.CONTINUE


def setup(plugin: Plugin) -> None:
    plugin.add_autogenerate_comparator(
        _autogen_for_views,
        "schema",
        "views",
    )
