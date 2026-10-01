import itertools
from contextvars import ContextVar

from django.db import NotSupportedError
from django.db.models.expressions import Col
from django.db.models.fields import Field
from django.db.models.query import QuerySet
from django.db.models.sql.datastructures import BaseTable
from django.db.models.sql.query import Query


_cte_compilation = ContextVar("cte_compilation", default=None)
_cte_counter = itertools.count(1)


class CTETable(BaseTable):
    def __init__(self, alias, cte):
        super().__init__(alias, alias)
        self.cte = cte

    def __eq__(self, other):
        return (
            isinstance(other, CTETable)
            and self.alias == other.alias
            and self.cte is other.cte
        )

    def __hash__(self):
        return hash((self.alias, id(self.cte)))

    def relabeled_clone(self, change_map):
        return self


class CTEQuery(Query):
    def __init__(self, *args, cte=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.cte = cte

    def clone(self):
        clone = super().clone()
        clone.cte = self.cte
        return clone

    def resolve_expression(self, query, *args, **kwargs):
        clone = self.clone()
        clone.bump_prefix(query, exclude={self.cte.alias})
        clone.subquery = True
        clone.where.resolve_expression(query, *args, **kwargs)
        if clone.combinator:
            clone.combined_queries = tuple(
                combined_query.resolve_expression(query, *args, **kwargs)
                for combined_query in clone.combined_queries
            )
        for key, value in clone.annotations.items():
            resolved = value.resolve_expression(query, *args, **kwargs)
            if hasattr(resolved, "external_aliases"):
                resolved.external_aliases.update(clone.external_aliases)
            clone.annotations[key] = resolved
        for alias, table in query.alias_map.items():
            clone.external_aliases[alias] = (
                hasattr(table, "join_field")
                and table.join_field.related_model._meta.db_table != alias
            ) or (type(table) is BaseTable and table.table_name != table.table_alias)
        clone.external_aliases.pop(self.cte.alias, None)
        return clone


class RecursiveCTEDefinition:
    def __init__(self, anchor, recursive=None, name=None):
        anchor.query.check_alias(name or "recursive_cte")
        self.alias = make_alias(name)
        self.anchor = anchor.all()
        self.recursive = recursive
        self._recursive_queryset = None
        self.result = None

    def get_recursive_queryset(self):
        if self._recursive_queryset is None:
            recursive = self.recursive
            if callable(recursive):
                recursive = recursive(self.result)
            if not isinstance(recursive, QuerySet):
                raise ValueError("The recursive CTE term must be a QuerySet.")
            self._recursive_queryset = recursive.all()
        return self._recursive_queryset


def make_alias(name):
    if name is not None:
        return name
    return "recursivecte%d" % next(_cte_counter)


def make_result_query(anchor_query, cte):
    query = anchor_query.chain(CTEQuery)
    query.cte = cte
    query.where = query.where.__class__()
    query.group_by = None
    query.order_by = ()
    query.extra_order_by = ()
    query.combinator = None
    query.combined_queries = ()
    query.combinator_all = False
    query.distinct = False
    query.distinct_fields = ()
    query.low_mark = 0
    query.high_mark = None
    query.select_for_update = False
    query.select_for_update_nowait = False
    query.select_for_update_skip_locked = False
    query.select_for_update_of = ()
    query.select_for_no_key_update = False
    query.explain_info = None
    old_aliases = set(query.alias_map)
    table = CTETable(cte.alias, cte)
    query.alias_map = {cte.alias: table}
    query.alias_refcount = {cte.alias: 1}
    query.table_map = {cte.alias: [cte.alias]}
    query.__dict__.pop("base_table", None)
    relabels = {alias: cte.alias for alias in old_aliases}
    query.select = tuple(
        expression.relabeled_clone(relabels) for expression in query.select
    )
    annotations = {}
    for key, expression in query.annotations.items():
        if key in query.annotation_select:
            output_field = getattr(expression, "output_field", None) or Field()
            target = output_field.clone()
            target.column = key
            target.attname = key
            annotations[key] = Col(cte.alias, target, output_field)
    query.annotations = annotations
    return query


class RecursiveCTE(QuerySet):
    def __init__(self, anchor, recursive=None, name=None):
        if not isinstance(anchor, QuerySet):
            raise TypeError("The recursive CTE anchor must be a QuerySet.")
        anchor = anchor.all()
        self.cte = RecursiveCTEDefinition(anchor, recursive, name)
        query = make_result_query(anchor.query, self.cte)
        super().__init__(
            model=anchor.model,
            query=query,
            using=anchor._db,
            hints=anchor._hints,
        )
        self._iterable_class = anchor._iterable_class
        self._fields = anchor._fields
        self.cte.result = self._clone()

    def _clone(self):
        clone = QuerySet.__new__(RecursiveCTE)
        QuerySet.__init__(
            clone,
            model=self.model,
            query=self.query.chain(),
            using=self._db,
            hints=self._hints,
        )
        clone.cte = self.cte
        clone._sticky_filter = self._sticky_filter
        clone._for_write = self._for_write
        clone._prefetch_related_lookups = self._prefetch_related_lookups[:]
        clone._known_related_objects = self._known_related_objects
        clone._iterable_class = self._iterable_class
        clone._fetch_mode = self._fetch_mode
        clone._fields = self._fields
        return clone

    def __deepcopy__(self, memo):
        return self._clone()

    def queryset(self):
        return self._clone()

    def update(self, **kwargs):
        raise NotSupportedError("Recursive CTEs only support SELECT.")

    def delete(self):
        raise NotSupportedError("Recursive CTEs only support SELECT.")


def begin_cte_compilation(compiler):
    state = _cte_compilation.get()
    if state is None or state.get("compiler") is compiler:
        ctes, hoisted = collect_root_recursive_ctes(compiler.query)
    else:
        return _cte_compilation.set(state)
    state = {
        "compiler": compiler,
        "ctes": ctes,
        "hoisted": hoisted,
    }
    return _cte_compilation.set(state)


def end_cte_compilation(token):
    if token is not None:
        _cte_compilation.reset(token)


def compiler_recursive_ctes(query):
    state = _cte_compilation.get()
    if state is None or state["compiler"].query is not query:
        local = collect_scope_recursive_ctes(query)
        if state is None:
            return local, set()
        hoisted = state["hoisted"]
        return [cte for cte in local if id(cte) not in hoisted], hoisted
    return state["ctes"], state["hoisted"]


def _query_expressions(query):
    yield query.select
    yield tuple(query.annotations.values())
    yield (query.where,)
    yield tuple(query.order_by)
    yield tuple(query.combined_queries)
    if hasattr(query, "inner_query"):
        yield (query.inner_query,)


def collect_scope_recursive_ctes(query):
    ctes = []
    seen = set()
    pending = [(query, False)]

    def add(cte):
        cte_id = id(cte)
        if cte_id in seen:
            return
        seen.add(cte_id)
        ctes.append(cte)
        pending.append((cte.anchor.query, True))
        pending.append((cte.get_recursive_queryset().query, True))

    while pending:
        node, nested = pending.pop()
        if isinstance(node, Query):
            if nested and node.subquery:
                continue
            cte = getattr(node, "cte", None)
            if cte is not None:
                add(cte)
            pending.extend(
                (expression, True) for expression in _query_expressions(node)
            )
        elif isinstance(node, (tuple, list, set)):
            pending.extend((item, nested) for item in node)
        elif hasattr(node, "get_source_expressions"):
            pending.extend(
                (expression, nested) for expression in node.get_source_expressions()
            )
    return ctes


def recursive_cte_scopes(query):
    scopes = {}
    objects = {}
    pending = [(query, None)]
    visited_queries = set()
    visited_components = set()

    while pending:
        node, scope = pending.pop()
        if not isinstance(node, Query):
            if isinstance(node, (tuple, list, set)):
                pending.extend((item, scope) for item in node)
            elif hasattr(node, "get_source_expressions"):
                pending.extend(
                    (expression, scope)
                    for expression in node.get_source_expressions()
                )
            continue
        if node.subquery:
            scope = id(node)
        query_id = id(node)
        if query_id in visited_queries:
            continue
        visited_queries.add(query_id)
        cte = getattr(node, "cte", None)
        if cte is not None:
            cte_id = id(cte)
            objects[cte_id] = cte
            scopes.setdefault(cte_id, set()).add(scope)
            if cte_id not in visited_components:
                visited_components.add(cte_id)
                pending.append((cte.anchor.query, scope))
                pending.append(
                    (cte.get_recursive_queryset().query, scope)
                )
                continue
        pending.extend((expression, scope) for expression in _query_expressions(node))
    return scopes, objects


def collect_root_recursive_ctes(query):
    scopes, objects = recursive_cte_scopes(query)
    hoisted = {
        cte_id for cte_id, used_scopes in scopes.items() if len(used_scopes) > 1
    }
    local = collect_scope_recursive_ctes(query)
    result = [cte for cte in local if id(cte) not in hoisted]
    result.extend(
        objects[cte_id]
        for cte_id in hoisted
        if objects[cte_id] not in result
    )
    return result, hoisted


def order_recursive_ctes(ctes, collector=collect_scope_recursive_ctes):
    by_id = {id(cte): cte for cte in ctes}
    dependencies = {}
    for cte in ctes:
        component_ctes = set()
        for component in (
            cte.anchor.query,
            cte.get_recursive_queryset().query,
        ):
            component_ctes.update(id(item) for item in collector(component))
        dependencies[id(cte)] = (component_ctes - {id(cte)}) & by_id.keys()
    ordered = []
    while len(ordered) < len(ctes):
        ready = [
            cte
            for cte in ctes
            if cte not in ordered
            and dependencies[id(cte)] <= {id(item) for item in ordered}
        ]
        if not ready:
            raise ValueError("Recursive CTEs contain a circular dependency.")
        ordered.extend(ready)
    return ordered
