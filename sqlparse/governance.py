"""Offline, syntax-only review of view migrations and frozen evidence paths."""

from __future__ import annotations

from collections.abc import Generator
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

import sqlparse
from sqlparse import tokens as T
from sqlparse.sql import Identifier, IdentifierList, TokenList


BLOCKER = "blocker"
WARNING = "warning"
INFO = "info"

APPROVED = "approved"
BLOCKED = "blocked"
INCOMPLETE = "incomplete"
MANUAL_REVIEW = "manual_review"

NAME_REUSED = "NAME_REUSED"
INCOMPLETE_DEPENDENCY = "INCOMPLETE_DEPENDENCY"
EVIDENCE_PATH_BROKEN = "EVIDENCE_PATH_BROKEN"
UNIQUE_CHAIN_REMOVED = "UNIQUE_DEPENDENCY_CHAIN_REMOVED"
FROZEN_TARGETED = "FROZEN_OBJECT_TARGETED"
UNKNOWN_OBJECT = "UNKNOWN_MIGRATION_OBJECT"
UNSUPPORTED = "UNSUPPORTED_STATEMENT"

TEST_PATCH = 2


@dataclass(frozen=True)
class QualifiedName:
    """A case-insensitive SQL name, while retaining its display text."""

    parts: tuple[str, ...]
    raw: str

    @classmethod
    def parse(cls, value: Any) -> QualifiedName:
        if isinstance(value, QualifiedName):
            return value
        text = str(value).strip().rstrip(";")
        parts = _split_qualified(text)
        return cls(tuple(parts), ".".join(parts))

    @property
    def key(self) -> tuple[str, ...]:
        return tuple(part.lower() for part in self.parts)

    @property
    def leaf(self) -> str:
        return self.parts[-1].lower()

    def __str__(self) -> str:
        return self.raw


def _clean_name_part(part: str) -> str:
    part = part.strip()
    if len(part) >= 2 and part[0] == "[" and part[-1] == "]":
        return part[1:-1].replace("]]", "]")
    if len(part) >= 2 and part[0] in ("'", '"') and part[0] == part[-1]:
        return part[1:-1].replace(part[0] * 2, part[0])
    if len(part) >= 2 and part[0] == chr(96) and part[-1] == chr(96):
        return part[1:-1]
    return part


def _split_qualified(text: str) -> list[str]:
    parts: list[str] = []
    buffer: list[str] = []
    quote = ""
    bracketed = False

    for char in text:
        if quote:
            buffer.append(char)
            if char == quote:
                quote = ""
            continue
        if char in ("'", '"') or char == chr(96):
            quote = char
            buffer.append(char)
        elif char == "[":
            bracketed = True
            buffer.append(char)
        elif char == "]":
            bracketed = False
            buffer.append(char)
        elif char == "." and not bracketed:
            parts.append(_clean_name_part("".join(buffer)))
            buffer = []
        else:
            buffer.append(char)
    parts.append(_clean_name_part("".join(buffer)))
    return [part for part in parts if part]


def _is_name_token(token: Any) -> bool:
    return token is not None and (
        token.ttype in T.Name or token.ttype in (T.String.Symbol, T.Literal.String)
    )


def _name_from_identifier(identifier: Identifier) -> QualifiedName:
    significant = [
        token
        for token in identifier.tokens
        if not token.is_whitespace and token.ttype not in T.Comment
    ]
    if significant and _is_name_token(significant[0]):
        raw_parts = [significant[0].value]
        clean_parts = [_clean_name_part(significant[0].value)]
        index = 1
        while (
            index + 1 < len(significant)
            and significant[index].match(T.Punctuation, ".")
            and _is_name_token(significant[index + 1])
        ):
            raw_parts.append(significant[index + 1].value)
            clean_parts.append(_clean_name_part(significant[index + 1].value))
            index += 2
        if len(clean_parts) == 1:
            real_name = identifier.get_real_name()
            if real_name:
                clean_parts = [_clean_name_part(real_name)]
        return QualifiedName(tuple(clean_parts), ".".join(raw_parts))

    real_name = identifier.get_real_name() or identifier.get_name() or str(identifier)
    parent = identifier.get_parent_name()
    if parent and "." not in real_name:
        return QualifiedName.parse(f"{parent}.{real_name}")
    return QualifiedName.parse(real_name)


_CLAUSE_END = {
    "WHERE",
    "GROUP",
    "HAVING",
    "WINDOW",
    "ORDER",
    "LIMIT",
    "OFFSET",
    "FETCH",
    "UNION",
    "INTERSECT",
    "EXCEPT",
    "RETURNING",
    "QUALIFY",
}


def extract_relations(sql: str) -> list[QualifiedName]:
    """Extract relation names from FROM and JOIN clauses."""
    relations: list[QualifiedName] = []
    for statement in sqlparse.parse(sql):
        _collect_relations(statement, relations, False)
    return relations


def extract_dependencies(sql: str) -> list[str]:
    """Return relation dependencies as dotted name strings."""
    return [str(name) for name in extract_relations(sql)]


def _collect_relations(
    token_list: TokenList,
    relations: list[QualifiedName],
    expect_relation: bool,
) -> None:
    state = "from" if expect_relation else None

    for token in token_list.tokens:
        if token.is_whitespace:
            continue

        if token.is_group:
            if isinstance(token, IdentifierList):
                if state in ("from", "join"):
                    for identifier in token.get_identifiers():
                        if isinstance(identifier, Identifier):
                            relations.append(_name_from_identifier(identifier))
                        else:
                            relations.append(QualifiedName.parse(str(identifier)))
                    state = "relation"
                else:
                    for identifier in token.get_identifiers():
                        _collect_relations(identifier, relations, False)
            elif isinstance(token, Identifier):
                if state in ("from", "join"):
                    relations.append(_name_from_identifier(token))
                    state = "relation"
                else:
                    _collect_relations(token, relations, False)
            elif isinstance(token, TokenList):
                _collect_relations(
                    token, relations, state in ("from", "join")
                )
                if state in ("from", "join"):
                    state = "relation"
            continue

        keyword = token.normalized.upper() if token.is_keyword else ""
        if keyword == "FROM":
            state = "from"
        elif keyword == "JOIN" or keyword.endswith(" JOIN"):
            state = "join"
        elif keyword in ("ON", "USING"):
            state = "condition"
        elif keyword == "SELECT" or keyword in _CLAUSE_END:
            state = "clause"
        elif token.ttype is T.Punctuation and token.value == "," and state == "relation":
            state = "from"


def _statement_keyword_text(statement: TokenList) -> str:
    return " ".join(
        token.normalized.upper()
        for token in statement.tokens
        if token.is_keyword
    )


@dataclass
class ViewDeclaration:
    name: str
    sql: str | None = None
    query: str | None = None
    dependencies: list[str] = field(default_factory=list)
    kind: str = "view"
    temporary: bool = False
    replace: bool = False
    materialized: bool = False
    frozen: bool = False
    object_id: str | None = None
    evidence: list[str] = field(default_factory=list)
    incomplete: bool = False


def parse_view_declaration(sql: str) -> ViewDeclaration:
    """Parse one CREATE VIEW-like statement into a declarative descriptor."""
    parsed = sqlparse.parse(sql)
    statement = next((item for item in parsed if item.token_first(skip_cm=True)), None)
    if statement is None:
        raise ValueError("empty view declaration")

    first = statement.token_first(skip_cm=True)
    if first.normalized.upper() != "CREATE":
        raise ValueError("expected a CREATE statement")

    keyword_text = _statement_keyword_text(statement)
    temporary = bool(re.search(r"\bTEMP(?:ORARY)?\b", keyword_text))
    materialized = "MATERIALIZED" in keyword_text.split()
    replace = "REPLACE" in keyword_text.split()

    object_keyword_index = None
    object_kind = "view"
    for index, token in enumerate(statement.tokens):
        if not token.is_keyword:
            continue
        word = token.normalized.upper()
        if word == "VIEW":
            object_keyword_index = index
            object_kind = "materialized_view" if materialized else "view"
            break
        if word == "SNAPSHOT":
            object_keyword_index = index
            object_kind = "snapshot"
        elif word == "TABLE" and object_keyword_index is not None:
            object_keyword_index = index
            object_kind = "snapshot_table" if "SNAPSHOT" in keyword_text else "table"
        elif word == "TABLE" and object_keyword_index is None:
            object_keyword_index = index
            object_kind = "table"

    name = None
    if object_keyword_index is not None:
        for token in statement.tokens[object_keyword_index + 1 :]:
            if isinstance(token, Identifier):
                name = _name_from_identifier(token)
                break
            if token.is_group and hasattr(token, "get_real_name"):
                name = QualifiedName.parse(token.get_real_name() or str(token))
                break

    if name is None:
        token = statement.token_next_by(i=Identifier)
        if token[1] is not None:
            name = _name_from_identifier(token[1])

    if name is None:
        raise ValueError("could not find object name in declaration")

    as_index = None
    for index, token in enumerate(statement.tokens):
        if token.is_keyword and token.normalized.upper() == "AS":
            as_index = index
            break

    query_sql = None
    if as_index is not None:
        query_sql = "".join(
            token.value for token in statement.tokens[as_index + 1 :]
        ).strip().rstrip(";").strip()

    references = _collect_declaration_references(statement)
    return ViewDeclaration(
        name=name.raw,
        sql=sql.strip(),
        query=query_sql,
        dependencies=[str(item) for item in references],
        kind=object_kind,
        temporary=temporary,
        replace=replace,
        materialized=materialized,
    )


def _collect_declaration_references(statement: TokenList) -> list[QualifiedName]:
    references: list[QualifiedName] = []
    _collect_relations(statement, references, False)
    cte_names = _extract_cte_names(statement)
    if cte_names:
        references = [
            ref
            for ref in references
            if ref.key not in cte_names and (ref.parts[-1].lower(),) not in cte_names
        ]
    return references


def _extract_cte_names(statement: TokenList) -> set[tuple[str, ...]]:
    names: set[tuple[str, ...]] = set()
    text = str(statement)
    for match in re.finditer(
        r"(?:\bWITH\b|,)\s+([A-Za-z_][A-Za-z0-9_$]*)",
        text,
        flags=re.IGNORECASE,
    ):
        candidate = QualifiedName.parse(match.group(1))
        names.add(candidate.key)
    return names


@dataclass
class Finding:
    code: str
    severity: str
    message: str
    object: str | None = None
    object_id: str | None = None
    related: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


class AuditReport(dict):
    """Dictionary report that also exposes common verdict aliases."""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    @property
    def blockers(self) -> list[dict[str, Any]]:
        return [item for item in self.get("findings", []) if item.get("severity") == BLOCKER]

    @property
    def warnings(self) -> list[dict[str, Any]]:
        return [item for item in self.get("findings", []) if item.get("severity") == WARNING]

    @property
    def safe(self) -> bool:
        return self.get("status") == APPROVED

    ok = approved = valid = passed = safe
    blocked = property(lambda self: self.get("status") == BLOCKED)

    def to_dict(self) -> dict[str, Any]:
        return dict(self)

    def to_json(self, indent: int = 2) -> str:
        import json

        return json.dumps(self.to_dict(), indent=indent, default=str, ensure_ascii=False)


def _new_state() -> dict[str, Any]:
    return {
        "nodes": {},
        "active_keys": {},
        "active_leaves": {},
        "findings": [],
        "actions": [],
        "renames": [],
        "name_reuses": [],
        "paths": [],
        "seen_findings": set(),
    }


def _add_finding(
    state: dict[str, Any],
    code: str,
    severity: str,
    message: str,
    obj: str | None = None,
    object_id: str | None = None,
    related: list[str] | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    key = (code, object_id or obj, message)
    if key in state["seen_findings"]:
        return next(item for item in state["findings"] if (item["code"], item.get("object_id"), item["message"]) == key)
    state["seen_findings"].add(key)
    finding = {
        "code": code,
        "severity": severity,
        "message": message,
        "object": obj,
        "object_id": object_id,
        "related": related or [],
        "details": details or {},
    }
    state["findings"].append(finding)
    return finding


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (str, bytes, Mapping)):
        return [value]
    try:
        return list(value)
    except TypeError:
        return [value]


def _pick(item: Any, names: tuple[str, ...]) -> Any:
    for name in names:
        if isinstance(item, Mapping):
            if name in item and item[name] is not None:
                return item[name]
        else:
            value = getattr(item, name, None)
            if value is not None:
                return value
    return None


def _name_key(value: Any) -> str:
    return ".".join(QualifiedName.parse(value).key)


def _looks_like_sql(value: str) -> bool:
    return bool(re.match(r"\s*(?:--[^\n]*\n|/\*.*?\*/\s*)*(?:CREATE|SELECT|WITH)\b", value, re.I | re.S))


def _find_active(state: dict[str, Any], name: QualifiedName) -> str | None:
    uid = state["active_keys"].get(name.key)
    if uid:
        return uid
    candidates = state["active_leaves"].get(name.leaf, set())
    if len(candidates) == 1:
        return next(iter(candidates))
    return None


def _index_node(state: dict[str, Any], node: dict[str, Any]) -> None:
    name = QualifiedName.parse(node["name"])
    state["active_keys"][name.key] = node["id"]
    state["active_leaves"].setdefault(name.leaf, set()).add(node["id"])


def _unindex_node(state: dict[str, Any], node: dict[str, Any]) -> None:
    name = QualifiedName.parse(node["name"])
    state["active_keys"].pop(name.key, None)
    leaves = state["active_leaves"].get(name.leaf)
    if leaves:
        leaves.discard(node["id"])
        if not leaves:
            state["active_leaves"].pop(name.leaf, None)


def _create_node(
    state: dict[str, Any],
    name_value: Any,
    *,
    object_id: str | None = None,
    kind: str = "object",
    sql: str | None = None,
    query: str | None = None,
    references: list[str] | None = None,
    frozen: bool = False,
    evidence: list[str] | None = None,
    temporary: bool = False,
    incomplete_reasons: list[str] | None = None,
) -> str:
    name = QualifiedName.parse(name_value)
    existing = _find_active(state, name)
    if existing:
        node = state["nodes"][existing]
        node["frozen"] = node["frozen"] or frozen
        node["temporary"] = node["temporary"] or temporary
        if sql:
            node["sql"] = sql
        if query:
            node["query"] = query
        node["raw_references"].extend(references or [])
        node["evidence"].extend(evidence or [])
        node["incomplete_reasons"].extend(incomplete_reasons or [])
        return existing

    base_id = object_id or ".".join(name.key)
    uid = base_id
    suffix = 2
    while uid in state["nodes"]:
        uid = f"{base_id}#{suffix}"
        suffix += 1

    node = {
        "id": uid,
        "name": name.raw,
        "canonical": ".".join(name.key),
        "kind": kind,
        "sql": sql,
        "query": query,
        "raw_references": list(references or []),
        "dependency_ids": [],
        "frozen": frozen,
        "evidence": list(evidence or []),
        "temporary": temporary,
        "status": "active",
        "name_history": [name.raw],
        "incarnation": 1,
        "reincarnation_of": None,
        "reused_by": None,
        "definition_changed": False,
        "incomplete_reasons": list(incomplete_reasons or []),
    }
    state["nodes"][uid] = node
    _index_node(state, node)
    return uid


def _reference_strings(value: Any) -> list[str]:
    refs = []
    for item in _as_list(value):
        if isinstance(item, Mapping):
            item = item.get("name") or item.get("target") or item.get("object")
        if item is not None:
            refs.append(str(item))
    return refs


def _ingest_value(state, value, frozen_default=False):
    if value is None:
        return
    if isinstance(value, (list, tuple, set, Generator)):
        for item in value:
            _ingest_value(state, item, frozen_default)
        return
    if isinstance(value, ViewDeclaration):
        _add_declaration(state, value, frozen=frozen_default)
        return
    if isinstance(value, (str, bytes)):
        text = value.decode() if isinstance(value, bytes) else value
        if _looks_like_sql(text):
            _ingest_sql(state, text, frozen_default)
        elif frozen_default:
            _create_node(state, QualifiedName.parse(text), frozen=True,
                         incomplete_reasons=["missing_definition"])
        return
    _add_spec(state, value, frozen_default)


def _ingest_sql(state, sql, frozen_default=False):
    for statement in sqlparse.parse(sql):
        first = statement.token_first(skip_cm=True)
        if first is None:
            continue
        if first.normalized.upper() == "CREATE":
            declaration = parse_view_declaration(str(statement))
            _add_declaration(state, declaration, frozen=frozen_default)


def _add_declaration(state, declaration, frozen=False):
    _create_node(
        state,
        QualifiedName.parse(declaration.name),
        kind=declaration.kind,
        sql=declaration.sql,
        query=declaration.query,
        references=declaration.dependencies,
        frozen=frozen or declaration.frozen,
        temporary=declaration.temporary,
    )


def _add_spec(state, item, frozen_default=False):
    name = _pick(item, ("name", "object", "object_name", "id"))
    if name is None:
        return
    sql = _pick(item, ("sql", "ddl", "definition", "create_sql"))
    query = _pick(item, ("query", "select", "query_sql"))
    references = _reference_strings(_pick(item, ("dependencies", "depends_on", "refs", "edges")))
    if not references and sql:
        references = extract_dependencies(sql)
    if query and not references:
        references = extract_dependencies(query)
    _create_node(state, QualifiedName.parse(name), sql=sql, query=query,
                 references=references, frozen=bool(frozen_default or _pick(item, ("frozen",))),
                 evidence=_as_list(_pick(item, ("evidence", "required_evidence"))),
                 object_id=_pick(item, ("object_id", "uid")),
                 incomplete_reasons=_as_list(_pick(item, ("incomplete_reasons",))))


def _resolve_dependencies(state, strict=False, known_views=None):
    known_views = known_views or set()
    for node in list(state["nodes"].values()):
        ids = []
        for raw in node.get("raw_references", []):
            name = QualifiedName.parse(raw)
            active = _find_active(state, name)
            if active:
                ids.append(active)
                continue
            key = ".".join(name.key)
            uid = "source:" + key
            if strict or key in known_views:
                uid = "missing:" + key
                uid = _create_node(
                    state, name, kind="unknown",
                    incomplete_reasons=["declaration_missing"])
                state["nodes"][uid]["status"] = "incomplete"
                _add_finding(state, INCOMPLETE_DEPENDENCY, "warning",
                             "Missing declaration for " + key, obj=key)
            else:
                _create_node(state, name, object_id=uid, kind="source")
            ids.append(uid)
        node["dependency_ids"] = ids


def _coerce_actions(state, migration):
    actions = []
    for item in _as_list(migration):
        if item is None:
            continue
        if isinstance(item, str):
            for statement in sqlparse.parse(item):
                if statement.token_first(skip_cm=True):
                    actions.extend(_actions_from_statement(statement))
        elif isinstance(item, Mapping):
            actions.append(dict(item))
        else:
            actions.append({"op": getattr(item, "op", None) or getattr(item, "operation", "raw"), "target": getattr(item, "target", None) or getattr(item, "name", None)})
    state["actions"].extend(actions)
    return actions


def _actions_from_statement(statement):
    sql = str(statement).strip().rstrip(";")
    upper = sql.upper()
    first = statement.token_first(skip_cm=True)
    command = first.normalized.upper() if first is not None else ""
    if command == "DROP":
        names = _stmt_identifier_names(statement)
        kind = "view" if " VIEW " in upper or upper.startswith("DROP VIEW") else "object"
        return [{
            "op": "drop", "sql": sql, "names": names, "object_kind": kind,
            "if_exists": "IF EXISTS" in upper, "cascade": "CASCADE" in upper,
        }]
    if command == "ALTER" and " RENAME " in upper:
        identifiers = [token for token in statement.tokens if isinstance(token, Identifier)]
        if " COLUMN " in upper or len(identifiers) < 2:
            return [{"op": "alter_other", "sql": sql}]
        return [{
            "op": "rename", "sql": sql,
            "source": _name_from_identifier(identifiers[0]).raw,
            "target": _name_from_identifier(identifiers[-1]).raw,
        }]
    if command == "CREATE":
        try:
            declaration = parse_view_declaration(sql)
            return [{"op": "create", "sql": sql, "declaration": declaration,
                    "replace": declaration.replace}]
        except ValueError:
            pass
    return [{"op": "other", "sql": sql}]


def _stmt_identifier_names(statement):
    names = []
    for token in statement.tokens:
        if isinstance(token, IdentifierList):
            names.extend(_name_from_identifier(item).raw
                         for item in token.get_identifiers()
                         if isinstance(item, Identifier))
        elif isinstance(token, Identifier):
            names.append(_name_from_identifier(token).raw)
    return names


def _apply_actions(state, actions):
    for action in actions:
        op = str(action.get("op") or action.get("operation") or "other").lower()
        if op == "drop":
            _apply_drop(state, action)
        elif op in ("rename", "alter_rename"):
            _apply_rename(state, action)
        elif op in ("create", "replace", "create_or_replace"):
            _apply_create(state, action)


def _apply_drop(state, action):
    targets = action.get("names") or _as_list(action.get("target") or action.get("name"))
    for raw in _reference_strings(targets):
        name = QualifiedName.parse(raw)
        uid = _find_active(state, name)
        if not uid:
            if not action.get("if_exists"):
                _add_finding(state, UNKNOWN_OBJECT, "warning", "Unknown object in DROP: " + raw, obj=raw)
            continue
        node = state["nodes"][uid]
        if node.get("frozen"):
            _add_finding(state, FROZEN_TARGETED, "blocker", "Frozen object cannot be dropped: " + raw, obj=raw, object_id=uid)
        _unindex_node(state, node)
        node["status"] = "dropped"


def _apply_rename(state, action):
    source_raw = action.get("source") or action.get("target") or action.get("name")
    target_raw = action.get("new_name") or action.get("to") or action.get("new") or action.get("target")
    if not source_raw or not target_raw:
        return
    source = QualifiedName.parse(source_raw)
    target = QualifiedName.parse(target_raw)
    uid = _find_active(state, source)
    collision = _find_active(state, target)
    if not uid:
        _add_finding(state, UNKNOWN_OBJECT, "warning", "Cannot rename unknown object: " + str(source_raw), obj=str(source_raw))
        return
    if collision and collision != uid:
        _add_finding(state, "RENAME_COLLISION", "blocker", "Rename target already exists: " + target.raw, obj=target.raw)
    node = state["nodes"][uid]
    if node.get("frozen"):
        _add_finding(state, FROZEN_TARGETED, "blocker", "Frozen object cannot be renamed: " + source.raw, obj=source.raw, object_id=uid)
    _unindex_node(state, node)
    node["name"] = target.raw
    node["name_history"].append(target.raw)
    _index_node(state, node)
    record = {"object_id": uid, "from": source.raw, "to": target.raw}
    state["renames"].append(record)


def _apply_create(state, action):
    raw_name = action.get("name") or action.get("target")
    sql = action.get("sql")
    declaration = action.get("declaration")
    if declaration is None and sql:
        try:
            declaration = parse_view_declaration(sql)
        except ValueError:
            declaration = None
    if declaration is not None:
        raw_name = raw_name or declaration.name
        references = declaration.dependencies
        kind = declaration.kind
        replace = bool(declaration.replace or action.get("op") == "replace")
    else:
        references = _reference_strings(action.get("dependencies"))
        kind = action.get("kind", "view")
        replace = action.get("op") == "replace"
    if not raw_name:
        return
    name = QualifiedName.parse(raw_name)
    existing = _find_active(state, name)
    if existing:
        if not replace:
            _add_finding(state, "DUPLICATE_OBJECT", "blocker",
                         "Object already exists: " + name.raw, obj=name.raw)
        return
    previous = None
    for node in state["nodes"].values():
        if node.get("canonical") == ".".join(name.key) and node.get("status") == "dropped":
            previous = node
            break
    if previous is not None:
        number = previous.get("incarnation", 1) + 1
        uid = ".".join(name.key) + "#" + str(number)
        uid = _create_node(state, name, object_id=uid, kind=kind,
                           references=references)
        state["nodes"][uid]["incarnation"] = number
        state["nodes"][uid]["reincarnation_of"] = previous["id"]
        state["nodes"][uid]["dependency_ids"] = []
        previous["reused_by"] = uid
        record = {"name": name.raw, "object_id": uid,
                  "previous_object_id": previous["id"]}
        state["name_reuses"].append(record)
        return
    uid = _create_node(state, name, kind=kind, references=references)
    state["nodes"][uid]["dependency_ids"] = []


def _collect_routes(state, uid, path, routes):
    if uid in path:
        routes.append(path + [uid])
        return
    node = state["nodes"].get(uid)
    dependencies = node.get("dependency_ids", []) if node else []
    if not dependencies:
        routes.append(path + [uid])
        return
    for dependency_id in dependencies:
        _collect_routes(state, dependency_id, path + [uid], routes)


def _evaluate_evidence(state):
    for root_id, root in state["nodes"].items():
        if not root.get("frozen"):
            continue
        routes = []
        _collect_routes(state, root_id, [], routes)
        accessible = []
        broken = False
        incomplete = False
        reused = []
        for route in routes:
            route_ok = True
            for node_id in route:
                node = state["nodes"].get(node_id)
                if node is None:
                    incomplete = True
                    route_ok = False
                    continue
                if node.get("status") == "incomplete":
                    incomplete = True
                    route_ok = False
                if node.get("status") == "dropped":
                    broken = True
                    route_ok = False
                    if node.get("reused_by"):
                        reused.append(node["reused_by"])
            if route_ok:
                accessible.append(route)
        unique_chain = len(routes) <= 1
        status = "accessible" if accessible else "incomplete" if incomplete and not broken else "broken"
        report = {
            "frozen": root.get("name"),
            "frozen_id": root_id,
            "status": status,
            "available": bool(accessible),
            "identity_preserved": bool(accessible),
            "unique_chain": unique_chain,
            "routes": [[state["nodes"].get(node_id, {}).get("name", node_id) for node_id in route] for route in routes],
        }
        state["paths"].append(report)
        if not accessible and status == "broken":
            code = UNIQUE_CHAIN_REMOVED if unique_chain else EVIDENCE_PATH_BROKEN
            _add_finding(state, code, "blocker", "Frozen evidence path is unavailable: " + root.get("name", root_id), obj=root.get("name"), object_id=root_id)
        for new_id in reused:
            _add_finding(state, NAME_REUSED, "blocker", "Original identity was replaced by a reused name", object_id=new_id)


def _build_report(state):
    findings = state["findings"]
    for node in state["nodes"].values():
        for reason in node.get("incomplete_reasons", []):
            _add_finding(state, INCOMPLETE_DEPENDENCY, "warning", "Incomplete dependency: " + str(reason), obj=node.get("name"), object_id=node.get("id"))
    blockers = [item for item in findings if item.get("severity") == BLOCKER]
    incomplete = any(item.get("code") == INCOMPLETE_DEPENDENCY for item in findings)
    incomplete = incomplete or any(n.get("incomplete_reasons") for n in state["nodes"].values())
    if blockers:
        status = BLOCKED
    elif incomplete:
        status = INCOMPLETE
    elif state["name_reuses"]:
        status = NAME_REUSED.lower()
    else:
        status = APPROVED

    report = AuditReport({
        "status": status,
        "approved": status == APPROVED,
        "safe": status == APPROVED,
        "ok": status == APPROVED,
        "valid": status == APPROVED,
        "passed": status == APPROVED,
        "blocked": status == BLOCKED,
        "complete": not incomplete,
        "findings": findings,
        "issues": findings,
        "blockers": blockers,
        "errors": blockers,
        "warnings": [item for item in findings if item.get("severity") == WARNING],
        "objects": list(state["nodes"].values()),
        "paths": state["paths"],
        "actions": state["actions"],
        "renames": state["renames"],
        "name_reuses": state["name_reuses"],
        "incomplete_dependencies": [item for item in findings if item.get("code") == INCOMPLETE_DEPENDENCY],
        "name_reuse_detected": bool(state["name_reuses"]),
    })
    report["verdict"] = status
    report["all_evidence_accessible"] = all(item.get("available") for item in state["paths"]) if state["paths"] else True
    return report


def review_migration(declarations=None, frozen=None, migration=None, **kwargs):
    declarations = declarations if declarations is not None else kwargs.get(
        "view_declarations", kwargs.get("views", kwargs.get("declaration_sql")))
    frozen = frozen if frozen is not None else kwargs.get(
        "freeze_list", kwargs.get("frozen_snapshots", kwargs.get("snapshots")))
    migration = migration if migration is not None else kwargs.get(
        "migration_script", kwargs.get("migration_sql", kwargs.get("script")))

    state = _new_state()
    strict = bool(kwargs.get("strict_dependencies", kwargs.get("strict", False)))
    _ingest_value(state, declarations)
    _ingest_value(state, frozen, True)

    actions = _coerce_actions(state, migration)
    known_views = {_name_key(item) for item in _as_list(kwargs.get("known_views"))}
    for action in actions:
        if str(action.get("op", "")).lower() == "drop":
            for raw in action.get("names") or []:
                known_views.add(_name_key(raw))

    _resolve_dependencies(state, strict=strict, known_views=known_views)
    _apply_actions(state, actions)
    _evaluate_evidence(state)
    return _build_report(state)


class MigrationReviewer:
    def review(self, *args, **kwargs):
        return review_migration(*args, **kwargs)


MigrationAuditor = MigrationReviewer
audit_migration = review_migration
review_sql = review_migration
audit_sql = review_migration
review_view_migration = review_migration
