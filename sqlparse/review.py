"""Offline, bounded review of view migrations.

This module answers one narrow question without executing any SQL:

    Given a baseline schema declared with ``CREATE`` statements, a list of
    frozen evidence objects, and a planned migration script, can every frozen
    object still reach its evidence sources through a live query path?

The review is deliberately finite.  It understands a small, explicit DDL
subset:

* ``CREATE [OR REPLACE] [MATERIALIZED] VIEW name AS <query>``
* ``CREATE [OR REPLACE] SNAPSHOT name AS <query>``
* ``CREATE [OR REPLACE] TABLE name [AS <query>]``
* ``ALTER {VIEW,TABLE,SNAPSHOT} name RENAME TO new_name``
* ``ALTER {VIEW,TABLE,SNAPSHOT} name SET SCHEMA schema``
* ``DROP {VIEW,TABLE,SNAPSHOT} [IF EXISTS] name [, ...]``

Dependencies are collected from ``FROM`` and ``JOIN`` table factors,
including nested subqueries and common table expressions.  Anything outside
that grammar is reported as an unsupported statement rather than guessed at.

Object identity is the important part.  Every declared object gets a stable
``object_id`` and dependency edges point at that id, not at a name.  Renaming
an object therefore keeps every downstream edge valid and leaves a trace from
the old name to the new one.  Dropping an object and creating a new object
with the same name is *name reuse*: the name still resolves, but it resolves
to a different identity.

Example
-------

::

    import sqlparse

    result = sqlparse.review.review(
        declarations='''
            CREATE VIEW temp_audit AS
                SELECT id, actor FROM audit_log;
            CREATE VIEW forensic_snapshot AS
                SELECT * FROM temp_audit;
        ''',
        freeze=["forensic_snapshot"],
        migration="ALTER VIEW temp_audit RENAME TO archive_audit;",
    )

    assert result.safe
    assert result.evidence[0].reason == "renamed"
    assert result.evidence[0].renames == (("temp_audit", "archive_audit"),)

The module never opens a database connection and never calls ``exec``.  It
only reads the token tree produced by :func:`sqlparse.parse`.
"""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from enum import Enum

from sqlparse import sql as sql_module
from sqlparse import tokens as T
from sqlparse.exceptions import SQLParseError

__all__ = [
    "EvidenceReport",
    "Finding",
    "FindingCategory",
    "FindingKind",
    "FrozenObject",
    "QueryPath",
    "RelationView",
    "ReviewError",
    "ReviewLimitExceeded",
    "ReviewResult",
    "normalize_name",
    "parse_freeze_list",
    "review",
    "review_files",
]


# ---------------------------------------------------------------------------
# Public result model
# ---------------------------------------------------------------------------


class FindingKind(str, Enum):
    """Machine-readable finding kinds."""

    NAME_REUSE = "name_reuse"
    INCOMPLETE_DEPENDENCY = "incomplete_dependency"
    FROZEN_OBJECT_MISSING = "frozen_object_missing"
    FROZEN_OBJECT_REDEFINED = "frozen_object_redefined"
    NAME_CONFLICT = "name_conflict"
    MISSING_TARGET = "missing_target"
    UNSUPPORTED_STATEMENT = "unsupported_statement"
    SYNTAX_ERROR = "syntax_error"
    LIMIT_EXCEEDED = "limit_exceeded"
    RENAMED = "renamed"


class FindingCategory(str, Enum):
    """Coarse grouping used to keep the two main hazards separate."""

    NAME_REUSE = "name_reuse"
    INCOMPLETE_DEPENDENCY = "incomplete_dependency"
    IDENTITY = "identity"
    SYNTAX = "syntax"
    TRACE = "trace"


@dataclass(frozen=True)
class Finding:
    """A single review observation.

    ``severity`` is one of ``"info"``, ``"warning"`` or ``"error"``.  A
    structural problem that does not touch a frozen evidence path is a
    warning; the same problem on a frozen path is promoted to an error.
    """

    kind: FindingKind
    category: FindingCategory
    message: str
    severity: str = "warning"
    object_id: str | None = None
    name: str | None = None
    related_id: str | None = None
    related_name: str | None = None
    statement_index: int | None = None
    details: dict[str, str] = field(default_factory=dict)


def _finding_dict(finding: Finding) -> dict:
    data = asdict(finding)
    data["kind"] = finding.kind.value
    data["category"] = finding.category.value
    return data


@dataclass(frozen=True)
class QueryPath:
    """One evidence anchor and the query paths that still reach it."""

    anchor: str
    anchor_id: str | None
    obtainable: bool
    path: tuple[str, ...] = ()
    path_ids: tuple[str, ...] = ()
    count: int = 0
    blocked_by: tuple[str, ...] = ()
    renames: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class EvidenceReport:
    """Whether one frozen object can still be produced from live objects."""

    frozen: str
    object_id: str | None
    obtainable: bool
    reason: str
    resolved_name: str | None = None
    renames: tuple[tuple[str, str], ...] = ()
    paths: tuple[QueryPath, ...] = ()
    missing_anchors: tuple[str, ...] = ()
    broken_at: tuple[str, ...] = ()


@dataclass(frozen=True)
class RelationView:
    """Read-only snapshot of a relation after the migration was applied."""

    object_id: str
    kind: str
    name: str
    origin_name: str
    origin: str
    alive: bool
    dependencies: tuple[str, ...] = ()
    dependency_ids: tuple[str, ...] = ()
    rename_history: tuple[tuple[str, str], ...] = ()
    redefinition_count: int = 0


@dataclass(frozen=True)
class ReviewResult:
    """Result returned by :func:`review`."""

    findings: tuple[Finding, ...]
    evidence: tuple[EvidenceReport, ...]
    relations: tuple[RelationView, ...]

    @property
    def status(self) -> str:
        return "safe" if self.safe else "unsafe"

    @property
    def ok(self) -> bool:
        """Alias for :attr:`safe`."""
        return self.safe

    @property
    def safe(self) -> bool:
        if any(finding.severity == "error" for finding in self.findings):
            return False
        return all(report.obtainable for report in self.evidence)

    @property
    def name_reuse(self) -> tuple[Finding, ...]:
        return tuple(
            finding
            for finding in self.findings
            if finding.category is FindingCategory.NAME_REUSE
        )

    @property
    def incomplete_dependencies(self) -> tuple[Finding, ...]:
        return tuple(
            finding
            for finding in self.findings
            if finding.category is FindingCategory.INCOMPLETE_DEPENDENCY
        )

    @property
    def renames(self) -> tuple[Finding, ...]:
        return tuple(
            finding
            for finding in self.findings
            if finding.kind is FindingKind.RENAMED
        )

    def to_dict(self) -> dict:
        """Return a JSON-serialisable representation."""

        return {
            "status": self.status,
            "safe": self.safe,
            "findings": [_finding_dict(finding) for finding in self.findings],
            "name_reuse": [
                _finding_dict(finding) for finding in self.name_reuse
            ],
            "incomplete_dependencies": [
                _finding_dict(finding)
                for finding in self.incomplete_dependencies
            ],
            "renames": [_finding_dict(finding) for finding in self.renames],
            "evidence": [asdict(report) for report in self.evidence],
            "relations": [asdict(relation) for relation in self.relations],
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def format(self) -> str:
        """Render a compact, human-readable report."""

        lines = [f"status: {self.status}"]
        if self.evidence:
            lines.append("evidence:")
            for report in self.evidence:
                detail = f"  {report.frozen} [{report.object_id}] "
                detail += "obtainable" if report.obtainable else "NOT obtainable"
                detail += f" ({report.reason})"
                if report.resolved_name and report.resolved_name != report.frozen:
                    detail += f" -> {report.resolved_name}"
                lines.append(detail)
                for path in report.paths:
                    if path.obtainable:
                        lines.append(
                            f"    {path.anchor}: "
                            + " -> ".join(path.path)
                            + f" ({path.count} path(s))"
                        )
                    else:
                        blocked = ", ".join(path.blocked_by) or path.anchor
                        lines.append(f"    {path.anchor}: blocked at {blocked}")
        if self.findings:
            lines.append("findings:")
            for finding in self.findings:
                prefix = f"  {finding.severity.upper():7}"
                location = finding.name or finding.object_id or ""
                if location:
                    location = f" [{location}]"
                lines.append(f"{prefix} {finding.kind.value}{location}: {finding.message}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Freeze input
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FrozenObject:
    """One entry in the freeze list.

    ``requires`` optionally names the evidence anchors that must remain
    reachable.  When it is omitted, the review treats every leaf of the
    object's declared dependency closure as an anchor.
    """

    name: str
    requires: tuple[str, ...] = ()


def parse_freeze_list(freeze) -> tuple[FrozenObject, ...]:
    """Normalise the accepted freeze-list shapes into ``FrozenObject`` items.

    Accepted inputs:

    * a newline/comma separated string (``"snap_a, snap_b"``)
    * a string line of the form ``"snap requires audit_log, users"``
    * an iterable of strings, mappings or :class:`FrozenObject`
    * a mapping of ``name -> requires`` where requires is a string, mapping
      or iterable
    """

    if freeze is None:
        return ()
    if isinstance(freeze, FrozenObject):
        return (freeze,)
    if isinstance(freeze, str):
        return _parse_freeze_text(freeze)
    if isinstance(freeze, Mapping):
        return tuple(_freeze_from_mapping(name, spec) for name, spec in freeze.items())
    if isinstance(freeze, Iterable):
        return tuple(_freeze_from_item(item) for item in freeze)
    raise ReviewError(f"unsupported freeze list type: {type(freeze).__name__}")


def _parse_freeze_text(text: str) -> tuple[FrozenObject, ...]:
    result = []
    for raw_line in re.split(r"[\r\n]+", text):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        for entry in _split_freeze_entries(line):
            if entry:
                result.append(_parse_freeze_entry(entry))
    return tuple(result)


def _split_freeze_entries(line: str) -> list[str]:
    # A comma separates entries unless the line uses an explicit
    # "requires"/"->"/":" form, in which case the right-hand side is a list
    # of anchors.
    if any(marker in line for marker in (" requires ", " REQUIRES ", "->", ":")):
        return [line]
    return [part.strip() for part in line.split(",") if part.strip()]


def _parse_freeze_entry(line: str) -> FrozenObject:
    for marker in (" requires ", " REQUIRES ", "->", ":"):
        if marker in line:
            name, rhs = line.split(marker, 1)
            return FrozenObject(
                name.strip(),
                _split_anchor_list(rhs),
            )
    return FrozenObject(line.strip())


def _split_anchor_list(value) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(part for part in re.split(r"[\s,]+", value.strip()) if part)
    if isinstance(value, Mapping):
        value = value.get("requires", value.get("dependencies", ()))
    return tuple(str(part).strip() for part in value if str(part).strip())


def _freeze_from_item(item) -> FrozenObject:
    if isinstance(item, FrozenObject):
        return item
    if isinstance(item, str):
        return _parse_freeze_entry(item.strip())
    if isinstance(item, Mapping):
        if "name" not in item:
            raise ReviewError("freeze mapping entries need a 'name' key")
        return FrozenObject(
            str(item["name"]).strip(),
            _split_anchor_list(item.get("requires", item.get("dependencies"))),
        )
    if isinstance(item, Sequence) and len(item) == 2 and isinstance(item[0], str):
        return FrozenObject(item[0].strip(), _split_anchor_list(item[1]))
    raise ReviewError(f"unsupported freeze entry: {item!r}")


def _freeze_from_mapping(name, spec) -> FrozenObject:
    return FrozenObject(str(name).strip(), _split_anchor_list(spec))


# ---------------------------------------------------------------------------
# Errors and limits
# ---------------------------------------------------------------------------


class ReviewError(SQLParseError):
    """Raised for invalid review input."""


class ReviewLimitExceeded(ReviewError):
    """Raised when a bounded review would exceed one of its limits."""


_MAX_OBJECTS = 1000
_MAX_DEPTH = 64
_MAX_PATHS = 64
_MAX_STATEMENTS = 10000


# ---------------------------------------------------------------------------
# Name handling
# ---------------------------------------------------------------------------


_PART = r'(?:"[^"]*"|`[^`]*`|\[[^\]]*\]|[A-Za-z_][\w$#]*)'
_QUALIFIED_RE = re.compile(rf"^\s*({_PART}(?:\s*\.\s*{_PART})*)")
_DOTTED_SPLIT_RE = re.compile(r"\s*\.\s*")


def normalize_name(raw: str | None) -> str:
    """Return a stable, case-insensitive catalogue key for *raw*.

    Surrounding quotes are removed and each qualified part is lower-cased.
    This is intentionally a little more permissive than a real catalogue:
    the review only needs names to line up across three input documents.
    """

    if not raw:
        return ""
    match = _QUALIFIED_RE.match(raw)
    if match is None:
        return ""
    parts = _DOTTED_SPLIT_RE.split(match.group(1))
    return ".".join(_unquote_part(part).lower() for part in parts)


def _unquote_part(part: str) -> str:
    part = part.strip()
    if len(part) >= 2:
        pairs = {'"': '"', "`": "`", "[": "]"}
        if part[0] in pairs and part[-1] == pairs[part[0]]:
            return part[1:-1]
    return part


def _display_name(raw: str) -> str:
    match = _QUALIFIED_RE.match(raw or "")
    return match.group(1).strip() if match else ""


def _name_from_identifier(identifier) -> str:
    raw = getattr(identifier, "value", str(identifier))
    match = _QUALIFIED_RE.match(raw)
    if match is not None:
        return normalize_name(match.group(1))
    real = getattr(identifier, "get_real_name", lambda: None)()
    parent = getattr(identifier, "get_parent_name", lambda: None)()
    if real:
        return normalize_name(f"{parent}.{real}" if parent else real)
    return ""


def _looks_like_function(raw: str) -> bool:
    match = _QUALIFIED_RE.match(raw or "")
    if match is None:
        return False
    return raw[match.end():].lstrip().startswith("(")


# ---------------------------------------------------------------------------
# Parsed DDL operations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _CreateOp:
    kind: str
    name: str
    dependencies: tuple[str, ...]
    definition: str
    replace: bool
    if_not_exists: bool
    raw: str


@dataclass(frozen=True)
class _RenameOp:
    old: str
    new: str
    raw: str


@dataclass(frozen=True)
class _DropOp:
    names: tuple[str, ...]
    if_exists: bool
    raw: str


@dataclass(frozen=True)
class _UnsupportedOp:
    raw: str
    reason: str


_IGNORED_HEADS = frozenset(
    {"COMMIT", "ROLLBACK", "BEGIN", "START", "SAVEPOINT", "RELEASE"}
)


def _parse(sql: str):
    # Imported lazily so ``sqlparse.review`` can be imported from
    # ``sqlparse/__init__.py`` without a circular import.
    from sqlparse import parse

    return parse(sql)


def _is_comment(token) -> bool:
    return token.ttype is not None and token.ttype in T.Comment


def _is_significant(token) -> bool:
    return not token.is_whitespace and not _is_comment(token)


def _significant(token_list) -> list:
    return [token for token in token_list.tokens if _is_significant(token)]


def _is_keyword(token, *values: str) -> bool:
    if token.ttype is None or token.ttype not in T.Keyword:
        return False
    if not values:
        return True
    return str(token.value).upper() in values


def _has_dml(token_list, *, _depth: int = 0) -> bool:
    if _depth > _MAX_DEPTH:
        return False
    for token in token_list.tokens:
        if token.ttype is not None and token.ttype in T.DML:
            return True
        if token.is_group and _has_dml(token, _depth=_depth + 1):
            return True
    return False


def _parse_operations(sql_text: str) -> tuple[list, list[Finding]]:
    if not sql_text:
        return [], []
    operations = []
    findings = []
    statements = _parse(sql_text)
    if len(statements) > _MAX_STATEMENTS:
        raise ReviewLimitExceeded(
            f"script has {len(statements)} statements, limit is {_MAX_STATEMENTS}"
        )
    for index, statement in enumerate(statements):
        significant = _significant(statement)
        if not significant:
            continue
        first = significant[0]
        head = str(first.value).upper().split()[0] if _is_keyword(first) else ""
        raw = str(statement).strip()
        if head == "CREATE":
            operation = _parse_create(significant, raw)
        elif head == "ALTER":
            operation = _parse_alter(significant, raw)
        elif head == "DROP":
            operation = _parse_drop(significant, raw)
        elif head in _IGNORED_HEADS:
            continue
        else:
            operation = _UnsupportedOp(
                raw,
                f"unsupported statement head: {head or first.value!r}",
            )
        if isinstance(operation, _UnsupportedOp):
            findings.append(
                Finding(
                    kind=FindingKind.UNSUPPORTED_STATEMENT,
                    category=FindingCategory.SYNTAX,
                    message=operation.reason,
                    severity="error",
                    statement_index=index,
                    details={"sql": operation.raw},
                )
            )
        else:
            operations.append(operation)
    return operations, findings


def _parse_create(tokens: list, raw: str):
    kind = None
    kind_index = None
    for index, token in enumerate(tokens):
        if _is_keyword(token, "VIEW"):
            materialized = any(
                _is_keyword(previous, "MATERIALIZED")
                for previous in tokens[:index]
            )
            kind = "materialized_view" if materialized else "view"
            kind_index = index
            break
        if _is_keyword(token, "SNAPSHOT"):
            kind = "snapshot"
            kind_index = index
            break
        if _is_keyword(token, "TABLE"):
            kind = "table"
            kind_index = index
            break
    if kind is None or kind_index is None:
        return _UnsupportedOp(raw, "CREATE without a supported relation kind")

    name_index = kind_index + 1
    if_not_exists = False
    while name_index < len(tokens):
        token = tokens[name_index]
        if _is_keyword(
            token,
            "IF",
            "NOT",
            "EXISTS",
            "IF NOT EXISTS",
            "ONLY",
            "FORCE",
            "NO",
        ):
            if _is_keyword(token, "IF", "IF NOT EXISTS"):
                if_not_exists = True
            name_index += 1
            continue
        break
    if name_index >= len(tokens):
        return _UnsupportedOp(raw, "CREATE is missing a relation name")

    name = _object_name(tokens[name_index])
    if not name:
        return _UnsupportedOp(raw, "CREATE has an unreadable relation name")

    as_index = None
    for index in range(name_index + 1, len(tokens)):
        if _is_keyword(tokens[index], "AS"):
            as_index = index
            break

    if as_index is None:
        if kind != "table":
            return _UnsupportedOp(raw, "CREATE relation is missing an AS query")
        dependencies: tuple[str, ...] = ()
        definition = ""
    else:
        query_tokens = tokens[as_index + 1:]
        dependencies = _extract_dependencies(query_tokens)
        definition = " ".join(str(token.value).strip() for token in query_tokens).strip()

    if kind == "table" and as_index is not None:
        kind = "snapshot"

    first = tokens[0]
    replace = "OR REPLACE" in str(first.value).upper()
    return _CreateOp(
        kind=kind,
        name=name,
        dependencies=dependencies,
        definition=definition,
        replace=replace,
        if_not_exists=if_not_exists,
        raw=raw,
    )


def _parse_alter(tokens: list, raw: str):
    index = 1
    if index < len(tokens) and _is_keyword(tokens[index], "MATERIALIZED"):
        index += 1
        if index >= len(tokens) or not _is_keyword(tokens[index], "VIEW"):
            return _UnsupportedOp(raw, "ALTER has an unsupported relation kind")
        index += 1
    elif index < len(tokens) and _is_keyword(
        tokens[index], "VIEW", "TABLE", "SNAPSHOT"
    ):
        index += 1
    else:
        return _UnsupportedOp(raw, "ALTER has an unsupported relation kind")
    while index < len(tokens) and _is_keyword(
        tokens[index], "IF", "EXISTS", "IF EXISTS"
    ):
        index += 1
    if index >= len(tokens):
        return _UnsupportedOp(raw, "ALTER is missing a relation name")
    old = _object_name(tokens[index])
    if not old:
        return _UnsupportedOp(raw, "ALTER has an unreadable relation name")

    for pos in range(index + 1, len(tokens)):
        if _is_keyword(tokens[pos], "RENAME"):
            next_pos = pos + 1
            if next_pos < len(tokens) and _is_keyword(tokens[next_pos], "COLUMN", "CONSTRAINT"):
                return _UnsupportedOp(
                    raw, "column/constraint rename is outside the reviewed subset"
                )
            if next_pos < len(tokens) and _is_keyword(tokens[next_pos], "TO"):
                next_pos += 1
            if next_pos >= len(tokens):
                return _UnsupportedOp(raw, "RENAME is missing a target name")
            new = _object_name(tokens[next_pos])
            if not new:
                return _UnsupportedOp(raw, "RENAME has an unreadable target name")
            return _RenameOp(old, new, raw)
        if (
            _is_keyword(tokens[pos], "SET")
            and pos + 1 < len(tokens)
            and _is_keyword(tokens[pos + 1], "SCHEMA")
        ):
            if pos + 2 >= len(tokens):
                return _UnsupportedOp(raw, "SET SCHEMA is missing a schema name")
            schema = _object_name(tokens[pos + 2])
            if not schema:
                return _UnsupportedOp(raw, "SET SCHEMA has an unreadable schema name")
            unqualified = old.rsplit(".", 1)[-1]
            return _RenameOp(old, f"{schema}.{unqualified}", raw)
    return _UnsupportedOp(raw, "ALTER without a supported rename operation")


def _parse_drop(tokens: list, raw: str):
    index = 1
    if index < len(tokens) and _is_keyword(tokens[index], "MATERIALIZED"):
        index += 1
        if index >= len(tokens) or not _is_keyword(tokens[index], "VIEW"):
            return _UnsupportedOp(raw, "DROP has an unsupported relation kind")
        index += 1
    elif index < len(tokens) and _is_keyword(
        tokens[index], "VIEW", "TABLE", "SNAPSHOT"
    ):
        index += 1
    else:
        return _UnsupportedOp(raw, "DROP has an unsupported relation kind")
    if_exists = False
    names = []
    while index < len(tokens):
        token = tokens[index]
        if _is_keyword(
            token,
            "IF",
            "EXISTS",
            "IF EXISTS",
            "CASCADE",
            "RESTRICT",
            "PURGE",
            "CONCURRENTLY",
        ):
            if _is_keyword(token, "IF", "IF EXISTS"):
                if_exists = True
            index += 1
            continue
        if isinstance(token, sql_module.IdentifierList):
            names.extend(_name_from_identifier(item) for item in token.get_identifiers())
        elif isinstance(token, (sql_module.Identifier, sql_module.Function)):
            names.append(_name_from_identifier(token))
        elif token.ttype is not None and token.ttype in T.Name:
            names.append(normalize_name(token.value))
        elif _is_keyword(token):
            break
        index += 1
    names = [name for name in names if name]
    if not names:
        return _UnsupportedOp(raw, "DROP is missing a relation name")
    return _DropOp(tuple(names), if_exists, raw)


def _object_name(token) -> str:
    if isinstance(token, (sql_module.Identifier, sql_module.Function)):
        return _name_from_identifier(token)
    if token.ttype is not None and token.ttype in T.Name:
        return normalize_name(token.value)
    return normalize_name(str(token.value))


# ---------------------------------------------------------------------------
# Dependency extraction
# ---------------------------------------------------------------------------


_JOIN_WORDS = frozenset(
    {
        "JOIN",
        "INNER JOIN",
        "CROSS JOIN",
        "LEFT JOIN",
        "LEFT OUTER JOIN",
        "RIGHT JOIN",
        "RIGHT OUTER JOIN",
        "FULL JOIN",
        "FULL OUTER JOIN",
        "NATURAL JOIN",
        "NATURAL LEFT JOIN",
        "NATURAL RIGHT JOIN",
        "NATURAL FULL JOIN",
        "STRAIGHT_JOIN",
        "CROSS APPLY",
        "OUTER APPLY",
    }
)
_FROM_PREFIX_WORDS = frozenset({"LATERAL", "ONLY", "TABLE"})
def _extract_dependencies(tokens: Sequence) -> tuple[str, ...]:
    found: list[str] = []
    seen: set[str] = set()
    visited: set[int] = set()
    _walk_dependencies(tokens, frozenset(), 0, found, seen, visited)
    return tuple(found)


def _walk_dependencies(
    tokens: Sequence,
    inherited_ctes: frozenset[str],
    depth: int,
    found: list[str],
    seen: set[str],
    visited: set[int],
) -> None:
    if depth > _MAX_DEPTH:
        raise ReviewLimitExceeded(f"dependency nesting exceeds {_MAX_DEPTH} levels")
    key = id(tokens)
    if key in visited:
        return
    visited.add(key)

    ctes = set(inherited_ctes)
    ctes.update(_discover_ctes(tokens))
    cte_scope = frozenset(ctes)

    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not _is_significant(token):
            index += 1
            continue
        if _is_keyword(token, "FROM") or _is_keyword(token, *_JOIN_WORDS):
            _consume_from_factor(
                tokens, index + 1, cte_scope, depth, found, seen, visited
            )
        elif token.is_group:
            _walk_dependencies(
                token.tokens, cte_scope, depth + 1, found, seen, visited
            )
        index += 1


def _discover_ctes(tokens: Sequence) -> set[str]:
    for index, token in enumerate(tokens):
        if not _is_keyword(token, "WITH"):
            continue
        ctes = set()
        pos = index + 1
        while pos < len(tokens):
            current = tokens[pos]
            if not _is_significant(current):
                pos += 1
                continue
            if _is_keyword(current, "RECURSIVE"):
                pos += 1
                continue
            if isinstance(current, sql_module.IdentifierList):
                for identifier in current.get_identifiers():
                    name = _cte_name(identifier)
                    if name:
                        ctes.add(name)
                break
            if isinstance(current, sql_module.Identifier) and _looks_like_cte(current):
                name = _cte_name(current)
                if name:
                    ctes.add(name)
                pos += 1
                continue
            break
        return ctes
    return set()


def _looks_like_cte(identifier) -> bool:
    return " AS " in f" {str(identifier.value).upper()} "


def _cte_name(identifier) -> str:
    return normalize_name(getattr(identifier, "get_real_name", lambda: None)() or "")


def _consume_from_factor(
    tokens: Sequence,
    start: int,
    ctes: frozenset[str],
    depth: int,
    found: list[str],
    seen: set[str],
    visited: set[int],
) -> None:
    pos = start
    while pos < len(tokens):
        token = tokens[pos]
        if not _is_significant(token):
            pos += 1
            continue
        if _is_keyword(token, *_FROM_PREFIX_WORDS):
            pos += 1
            continue
        if _is_keyword(token):
            return
        if isinstance(token, sql_module.IdentifierList):
            for identifier in token.get_identifiers():
                _consume_identifier(
                    identifier, ctes, depth, found, seen, visited
                )
            return
        if isinstance(token, sql_module.Identifier):
            _consume_identifier(token, ctes, depth, found, seen, visited)
            return
        if isinstance(token, sql_module.Parenthesis):
            _walk_dependencies(
                token.tokens, ctes, depth + 1, found, seen, visited
            )
            return
        if isinstance(token, sql_module.Function):
            _consume_identifier(token, ctes, depth, found, seen, visited)
            return
        if token.ttype is not None and token.ttype in T.Name:
            _record_dependency(normalize_name(token.value), ctes, found, seen)
        return


def _consume_identifier(
    identifier,
    ctes: frozenset[str],
    depth: int,
    found: list[str],
    seen: set[str],
    visited: set[int],
) -> None:
    raw = str(getattr(identifier, "value", identifier))
    if _has_dml(identifier):
        _walk_dependencies(
            identifier.tokens, ctes, depth + 1, found, seen, visited
        )
        return
    if _looks_like_function(raw):
        _walk_dependencies(
            identifier.tokens, ctes, depth + 1, found, seen, visited
        )
        return
    name = _name_from_identifier(identifier)
    _record_dependency(name, ctes, found, seen)


def _record_dependency(
    name: str,
    ctes: frozenset[str],
    found: list[str],
    seen: set[str],
) -> None:
    if not name or name in ctes or name in seen:
        return
    seen.add(name)
    found.append(name)


# ---------------------------------------------------------------------------
# Internal catalogue
# ---------------------------------------------------------------------------


@dataclass
class _Edge:
    target_id: str
    name: str
    display: str


@dataclass
class _Relation:
    object_id: str
    kind: str
    name: str
    origin_name: str
    origin: str
    dependencies: list[_Edge] = field(default_factory=list)
    definition: str = ""
    alive: bool = True
    dropped_at: int | None = None
    rename_history: list[tuple[str, str]] = field(default_factory=list)
    redefinition_count: int = 0


@dataclass
class _CreateOutcome:
    relation: _Relation | None
    reused_old_id: str | None = None
    conflict: str | None = None


class _Catalog:
    def __init__(self, *, max_objects: int = _MAX_OBJECTS):
        self.relations: dict[str, _Relation] = {}
        self.by_name: dict[str, str] = {}
        self.retired: dict[str, str] = {}
        self.max_objects = max_objects
        self._next_id = 0

    def _new_id(self) -> str:
        if len(self.relations) >= self.max_objects:
            raise ReviewLimitExceeded(
                f"catalogue has {len(self.relations)} objects, "
                f"limit is {self.max_objects}"
            )
        self._next_id += 1
        return f"o{self._next_id}"

    def ensure_external(self, name: str, *, origin: str = "external") -> _Relation:
        object_id = self.by_name.get(name)
        if object_id is not None:
            return self.relations[object_id]
        object_id = self._new_id()
        relation = _Relation(
            object_id=object_id,
            kind="external",
            name=name,
            origin_name=name,
            origin=origin,
        )
        self.relations[object_id] = relation
        self.by_name[name] = object_id
        return relation

    def bind_dependencies(self, names: Iterable[str]) -> list[_Edge]:
        edges = []
        for name in names:
            relation = self.ensure_external(name)
            edges.append(_Edge(relation.object_id, name, name))
        return edges

    def create(
        self,
        *,
        kind: str,
        name: str,
        dependencies: Iterable[str],
        definition: str,
        replace: bool,
        if_not_exists: bool,
        origin: str,
    ) -> _CreateOutcome:
        existing_id = self.by_name.get(name)
        if existing_id is not None:
            relation = self.relations[existing_id]
            if relation.kind == "external":
                # A relation referenced before it was declared.  Promoting it
                # preserves the identity that earlier edges already bound to.
                edges = self.bind_dependencies(dependencies)
                relation.kind = kind
                relation.origin = origin
                relation.definition = definition
                relation.dependencies = edges
                return _CreateOutcome(relation)
            if replace:
                edges = self.bind_dependencies(dependencies)
                relation.kind = kind
                relation.definition = definition
                relation.dependencies = edges
                relation.redefinition_count += 1
                return _CreateOutcome(relation)
            if if_not_exists:
                return _CreateOutcome(relation)
            return _CreateOutcome(
                None,
                conflict=(
                    f"cannot create {name!r}: the name is already owned by "
                    f"{relation.object_id} ({relation.kind})"
                ),
            )

        edges = self.bind_dependencies(dependencies)
        object_id = self._new_id()
        relation = _Relation(
            object_id=object_id,
            kind=kind,
            name=name,
            origin_name=name,
            origin=origin,
            dependencies=edges,
            definition=definition,
        )
        self.relations[object_id] = relation
        self.by_name[name] = object_id
        return _CreateOutcome(relation, reused_old_id=self.retired.get(name))

    def rename(
        self, old: str, new: str
    ) -> tuple[_Relation | None, str | None, str | None]:
        object_id = self.by_name.get(old)
        if object_id is None:
            return None, f"cannot rename {old!r}: no live object has that name", "missing"
        if old == new:
            return self.relations[object_id], None, None
        owner = self.by_name.get(new)
        if owner is not None and owner != object_id:
            return None, (
                f"cannot rename {old!r} to {new!r}: "
                f"the target name is already owned by {owner}"
            ), "conflict"
        relation = self.relations[object_id]
        self.by_name.pop(old, None)
        self.by_name[new] = object_id
        relation.name = new
        relation.rename_history.append((old, new))
        return relation, None, None

    def drop(self, name: str) -> tuple[_Relation | None, str | None]:
        object_id = self.by_name.get(name)
        if object_id is None:
            return None, f"cannot drop {name!r}: no live object has that name"
        relation = self.relations[object_id]
        relation.alive = False
        self.by_name.pop(name, None)
        self.retired[name] = object_id
        return relation, None


# ---------------------------------------------------------------------------
# Findings collection
# ---------------------------------------------------------------------------


_SEVERITY_RANK = {"info": 0, "warning": 1, "error": 2}


class _Findings:
    def __init__(self) -> None:
        self._items: list[Finding] = []
        self._index: dict[tuple, int] = {}

    def add(self, key: tuple, finding: Finding) -> None:
        if key in self._index:
            index = self._index[key]
            current = self._items[index]
            if _SEVERITY_RANK[finding.severity] > _SEVERITY_RANK[current.severity]:
                self._items[index] = finding
            return
        self._index[key] = len(self._items)
        self._items.append(finding)

    def result(self) -> tuple[Finding, ...]:
        return tuple(self._items)


# ---------------------------------------------------------------------------
# Review
# ---------------------------------------------------------------------------


_EDGE_VALID = "valid"
_EDGE_RENAMED = "renamed"
_EDGE_NAME_REUSE = "name_reuse"
_EDGE_MISSING = "missing"


@dataclass(frozen=True)
class _Anchor:
    object_id: str
    name: str


@dataclass(frozen=True)
class _FrozenBinding:
    spec: FrozenObject
    name: str
    object_id: str
    anchors: tuple[_Anchor, ...]


def review(
    declarations,
    freeze=None,
    migration="",
    *,
    max_objects: int = _MAX_OBJECTS,
    max_paths: int = _MAX_PATHS,
    max_depth: int = _MAX_DEPTH,
) -> ReviewResult:
    """Review a planned migration against frozen evidence objects.

    :param declarations: SQL text declaring the baseline views/snapshots.
    :param freeze: the freeze list (see :func:`parse_freeze_list`).
    :param migration: SQL text containing the planned migration.
    :param max_objects: hard limit on catalogue objects.
    :param max_paths: hard cap when enumerating alternative query paths.
    :param max_depth: hard limit on dependency nesting.
    :returns: a :class:`ReviewResult`.

    No SQL is executed.  The review is conservative: statements outside the
    documented subset are reported as errors.
    """

    if isinstance(declarations, Mapping):
        raise ReviewError(
            "declarations must be SQL text, not a mapping; "
            "pass CREATE statements as a string"
        )
    if isinstance(declarations, Sequence) and not isinstance(declarations, str):
        declarations = "\n".join(str(item) for item in declarations)
    if isinstance(migration, Sequence) and not isinstance(migration, str):
        migration = "\n".join(str(item) for item in migration)

    global _MAX_PATHS, _MAX_DEPTH
    previous_paths, previous_depth = _MAX_PATHS, _MAX_DEPTH
    _MAX_PATHS, _MAX_DEPTH = max_paths, max_depth
    try:
        return _review(
            str(declarations or ""),
            freeze,
            str(migration or ""),
            max_objects=max_objects,
            max_paths=max_paths,
            max_depth=max_depth,
        )
    except ReviewLimitExceeded as error:
        finding = Finding(
            kind=FindingKind.LIMIT_EXCEEDED,
            category=FindingCategory.SYNTAX,
            message=str(error),
            severity="error",
        )
        return ReviewResult((finding,), (), ())
    finally:
        _MAX_PATHS, _MAX_DEPTH = previous_paths, previous_depth


def _review(
    declarations: str,
    freeze,
    migration: str,
    *,
    max_objects: int,
    max_paths: int,
    max_depth: int,
) -> ReviewResult:
    findings = _Findings()
    catalog = _Catalog(max_objects=max_objects)

    declaration_ops, declaration_findings = _parse_operations(declarations)
    for finding in declaration_findings:
        findings.add(("declaration", finding.message), finding)

    for op in declaration_ops:
        if not isinstance(op, _CreateOp):
            findings.add(
                ("declaration-op", op.raw),
                Finding(
                    kind=FindingKind.SYNTAX_ERROR,
                    category=FindingCategory.SYNTAX,
                    message="declarations may only contain CREATE statements",
                    severity="error",
                    details={"sql": op.raw},
                ),
            )
            continue
        outcome = catalog.create(
            kind=op.kind,
            name=op.name,
            dependencies=op.dependencies,
            definition=op.definition,
            replace=op.replace,
            if_not_exists=op.if_not_exists,
            origin="declaration",
        )
        if outcome.conflict:
            findings.add(
                ("declaration-conflict", op.name),
                Finding(
                    kind=FindingKind.NAME_CONFLICT,
                    category=FindingCategory.IDENTITY,
                    message=outcome.conflict,
                    severity="error",
                    name=op.name,
                    details={"sql": op.raw},
                ),
            )

    bindings = _bind_frozen(catalog, freeze, findings)

    migration_ops, migration_findings = _parse_operations(migration)
    for finding in migration_findings:
        findings.add(("migration", finding.message), finding)

    for statement_index, op in enumerate(migration_ops, start=1):
        if isinstance(op, _CreateOp):
            _apply_create(catalog, op, statement_index, findings)
        elif isinstance(op, _RenameOp):
            _relation, error, error_kind = catalog.rename(op.old, op.new)
            if error:
                kind = (
                    FindingKind.NAME_CONFLICT
                    if error_kind == "conflict"
                    else FindingKind.MISSING_TARGET
                )
                findings.add(
                    ("rename-error", error_kind, op.old, op.new, statement_index),
                    Finding(
                        kind=kind,
                        category=FindingCategory.IDENTITY,
                        message=error,
                        severity="error",
                        name=op.old,
                        related_name=op.new,
                        statement_index=statement_index,
                        details={"sql": op.raw},
                    ),
                )
        elif isinstance(op, _DropOp):
            for name in op.names:
                relation, error = catalog.drop(name)
                if error and not op.if_exists:
                    findings.add(
                        ("drop-missing", name, statement_index),
                        Finding(
                            kind=FindingKind.MISSING_TARGET,
                            category=FindingCategory.IDENTITY,
                            message=error,
                            severity="error",
                            name=name,
                            statement_index=statement_index,
                            details={"sql": op.raw},
                        ),
                    )

    _scan_structure(catalog, findings)
    evidence = _evaluate_evidence(
        catalog, bindings, findings, max_paths=max_paths
    )
    _record_rename_traces(catalog, findings)
    relations = _relation_views(catalog)
    return ReviewResult(findings.result(), evidence, relations)


def _apply_create(
    catalog: _Catalog,
    op: _CreateOp,
    statement_index: int,
    findings: _Findings,
) -> None:
    outcome = catalog.create(
        kind=op.kind,
        name=op.name,
        dependencies=op.dependencies,
        definition=op.definition,
        replace=op.replace,
        if_not_exists=op.if_not_exists,
        origin="migration",
    )
    if outcome.conflict:
        findings.add(
            ("create-conflict", op.name, statement_index),
            Finding(
                kind=FindingKind.NAME_CONFLICT,
                category=FindingCategory.IDENTITY,
                message=outcome.conflict,
                severity="error",
                name=op.name,
                statement_index=statement_index,
                details={"sql": op.raw},
            ),
        )
        return
    if outcome.reused_old_id is not None and outcome.relation is not None:
        findings.add(
            ("name-reuse-create", outcome.relation.object_id),
            Finding(
                kind=FindingKind.NAME_REUSE,
                category=FindingCategory.NAME_REUSE,
                message=(
                    f"name {op.name!r} was reused: it used to identify "
                    f"{outcome.reused_old_id}, now identifies "
                    f"{outcome.relation.object_id}"
                ),
                severity="warning",
                object_id=outcome.relation.object_id,
                name=op.name,
                related_id=outcome.reused_old_id,
                statement_index=statement_index,
                details={"sql": op.raw},
            ),
        )


def _bind_frozen(
    catalog: _Catalog,
    freeze,
    findings: _Findings,
) -> tuple[_FrozenBinding, ...]:
    bindings = []
    seen: set[str] = set()
    for spec in parse_freeze_list(freeze):
        name = normalize_name(spec.name)
        if not name:
            findings.add(
                ("freeze-name", spec.name),
                Finding(
                    kind=FindingKind.SYNTAX_ERROR,
                    category=FindingCategory.SYNTAX,
                    message=f"freeze entry has an unreadable name: {spec.name!r}",
                    severity="error",
                    name=spec.name,
                ),
            )
            continue
        if name in seen:
            continue
        seen.add(name)
        relation = catalog.by_name.get(name)
        if relation is None:
            frozen = catalog.ensure_external(name, origin="frozen")
        else:
            frozen = catalog.relations[relation]
        anchors = _baseline_anchors(catalog, frozen, spec.requires)
        bindings.append(
            _FrozenBinding(
                spec=spec,
                name=name,
                object_id=frozen.object_id,
                anchors=anchors,
            )
        )
    return tuple(bindings)


def _baseline_anchors(
    catalog: _Catalog,
    frozen: _Relation,
    requires: tuple[str, ...],
) -> tuple[_Anchor, ...]:
    if requires:
        anchors = []
        seen = set()
        for raw in requires:
            name = normalize_name(raw)
            if not name or name in seen:
                continue
            seen.add(name)
            relation = catalog.ensure_external(name)
            anchors.append(_Anchor(relation.object_id, relation.name))
        return tuple(anchors)

    anchors: list[_Anchor] = []
    seen_anchors: set[str] = set()
    visited: set[str] = set()

    def walk(object_id: str, depth: int) -> None:
        if depth > _MAX_DEPTH:
            raise ReviewLimitExceeded(
                f"baseline dependency nesting exceeds {_MAX_DEPTH} levels"
            )
        if object_id in visited:
            return
        visited.add(object_id)
        relation = catalog.relations[object_id]
        if not relation.dependencies:
            if object_id not in seen_anchors:
                seen_anchors.add(object_id)
                anchors.append(_Anchor(object_id, relation.name))
            return
        for edge in relation.dependencies:
            walk(edge.target_id, depth + 1)

    walk(frozen.object_id, 0)
    return tuple(anchors)


def _edge_status(
    edge: _Edge,
    catalog: _Catalog,
) -> str:
    relation = catalog.relations.get(edge.target_id)
    current_owner = catalog.by_name.get(edge.name)
    if relation is not None and relation.alive:
        if current_owner is None:
            if relation.name == edge.name:
                return _EDGE_VALID
            return _EDGE_RENAMED
        if current_owner == edge.target_id:
            return _EDGE_VALID
        return _EDGE_NAME_REUSE
    if current_owner is not None and current_owner != edge.target_id:
        return _EDGE_NAME_REUSE
    return _EDGE_MISSING


def _scan_structure(catalog: _Catalog, findings: _Findings) -> None:
    for relation in catalog.relations.values():
        if not relation.alive:
            continue
        for edge in relation.dependencies:
            status = _edge_status(edge, catalog)
            if status == _EDGE_NAME_REUSE:
                findings.add(
                    ("struct-reuse", relation.object_id, edge.name),
                    Finding(
                        kind=FindingKind.NAME_REUSE,
                        category=FindingCategory.NAME_REUSE,
                        message=(
                            f"{relation.name!r} references {edge.name!r}, but that "
                            "name now identifies a different object"
                        ),
                        severity="warning",
                        object_id=relation.object_id,
                        name=relation.name,
                        related_id=edge.target_id,
                        related_name=edge.name,
                    ),
                )
            elif status == _EDGE_MISSING:
                findings.add(
                    ("struct-missing", relation.object_id, edge.name),
                    Finding(
                        kind=FindingKind.INCOMPLETE_DEPENDENCY,
                        category=FindingCategory.INCOMPLETE_DEPENDENCY,
                        message=(
                            f"{relation.name!r} depends on {edge.name!r}, "
                            "which is no longer present"
                        ),
                        severity="warning",
                        object_id=relation.object_id,
                        name=relation.name,
                        related_id=edge.target_id,
                        related_name=edge.name,
                    ),
                )


def _evaluate_evidence(
    catalog: _Catalog,
    bindings: tuple[_FrozenBinding, ...],
    findings: _Findings,
    *,
    max_paths: int,
) -> tuple[EvidenceReport, ...]:
    reports = []
    for binding in bindings:
        report = _evaluate_one(
            catalog, binding, findings, max_paths=max_paths
        )
        reports.append(report)
    return tuple(reports)


def _evaluate_one(
    catalog: _Catalog,
    binding: _FrozenBinding,
    findings: _Findings,
    *,
    max_paths: int,
) -> EvidenceReport:
    frozen = catalog.relations.get(binding.object_id)
    current_owner = catalog.by_name.get(binding.name)
    direct_reuse = (
        current_owner is not None and current_owner != binding.object_id
    )

    if frozen is None or not frozen.alive:
        reason = "name_reuse" if direct_reuse else "frozen_object_missing"
        _add_evidence_error(binding, reason, None, findings, catalog)
        return EvidenceReport(
            frozen=binding.spec.name,
            object_id=binding.object_id,
            obtainable=False,
            reason=reason,
            resolved_name=(
                catalog.relations[current_owner].name if current_owner else None
            ),
            renames=_renames_for(binding.object_id, catalog),
        )

    if direct_reuse:
        _add_evidence_error(binding, "name_reuse", None, findings, catalog)
        return EvidenceReport(
            frozen=binding.spec.name,
            object_id=binding.object_id,
            obtainable=False,
            reason="name_reuse",
            resolved_name=catalog.relations[current_owner].name,
            renames=_renames_for(binding.object_id, catalog),
        )

    if frozen.redefinition_count:
        findings.add(
            ("frozen-redefined", binding.object_id),
            Finding(
                kind=FindingKind.FROZEN_OBJECT_REDEFINED,
                category=FindingCategory.TRACE,
                message=(
                    f"frozen object {binding.spec.name!r} was redefined by "
                    "the migration"
                ),
                severity="warning",
                object_id=binding.object_id,
                name=binding.spec.name,
            ),
        )

    path_reports = []
    missing_anchors = []
    broken_at: list[str] = []
    saw_name_reuse = False
    saw_rename = False
    for anchor in binding.anchors:
        paths = _find_paths(
            catalog,
            binding.object_id,
            anchor.object_id,
            max_paths=max_paths,
            max_depth=_MAX_DEPTH,
        )
        if not paths:
            blockers = _collect_blockers(
                catalog, binding.object_id, max_depth=_MAX_DEPTH
            )
            anchor_blockers = [
                blocker for blocker in blockers
                if blocker[3] == anchor.object_id
            ]
            relevant = anchor_blockers or blockers
            if any(blocker[2] == _EDGE_NAME_REUSE for blocker in relevant):
                saw_name_reuse = True
            blocked_names = tuple(
                dict.fromkeys(blocker[1] for blocker in relevant)
            ) or (anchor.name,)
            broken_at.extend(blocked_names)
            missing_anchors.append(anchor.name)
            path_reports.append(
                QueryPath(
                    anchor=anchor.name,
                    anchor_id=anchor.object_id,
                    obtainable=False,
                    blocked_by=blocked_names,
                )
            )
            continue

        first_path = paths[0]
        path_renames = _renames_for_path(first_path, catalog)
        if path_renames:
            saw_rename = True
        path_reports.append(
            QueryPath(
                anchor=anchor.name,
                anchor_id=anchor.object_id,
                obtainable=True,
                path=tuple(catalog.relations[oid].name for oid in first_path),
                path_ids=first_path,
                count=len(paths),
                renames=path_renames,
            )
        )

    renames = _renames_for(binding.object_id, catalog)
    for report in path_reports:
        for pair in report.renames:
            if pair not in renames:
                renames.append(pair)

    if missing_anchors:
        reason = "name_reuse" if saw_name_reuse else "incomplete_dependency"
        _add_evidence_error(
            binding, reason, missing_anchors[0], findings, catalog
        )
        return EvidenceReport(
            frozen=binding.spec.name,
            object_id=binding.object_id,
            obtainable=False,
            reason=reason,
            resolved_name=frozen.name,
            renames=tuple(renames),
            paths=tuple(path_reports),
            missing_anchors=tuple(missing_anchors),
            broken_at=tuple(dict.fromkeys(broken_at)),
        )

    reason = "renamed" if saw_rename else "ok"
    return EvidenceReport(
        frozen=binding.spec.name,
        object_id=binding.object_id,
        obtainable=True,
        reason=reason,
        resolved_name=frozen.name,
        renames=tuple(renames),
        paths=tuple(path_reports),
    )


def _add_evidence_error(
    binding: _FrozenBinding,
    reason: str,
    anchor_name: str | None,
    findings: _Findings,
    catalog: _Catalog,
) -> None:
    if reason == "name_reuse":
        kind = FindingKind.NAME_REUSE
        category = FindingCategory.NAME_REUSE
        message = (
            f"frozen object {binding.spec.name!r} cannot rely on its query path: "
            "a name on that path was reused for a different object"
        )
    elif reason == "frozen_object_missing":
        kind = FindingKind.FROZEN_OBJECT_MISSING
        category = FindingCategory.IDENTITY
        message = (
            f"frozen object {binding.spec.name!r} was dropped and its name "
            "no longer resolves"
        )
    else:
        kind = FindingKind.INCOMPLETE_DEPENDENCY
        category = FindingCategory.INCOMPLETE_DEPENDENCY
        message = (
            f"frozen object {binding.spec.name!r} lost its only live query path"
            + (f" to {anchor_name!r}" if anchor_name else "")
        )
    findings.add(
        ("evidence", binding.name, reason, anchor_name),
        Finding(
            kind=kind,
            category=category,
            message=message,
            severity="error",
            object_id=binding.object_id,
            name=binding.spec.name,
            related_name=anchor_name,
            details={"frozen": binding.spec.name, "reason": reason},
        ),
    )


def _find_paths(
    catalog: _Catalog,
    start: str,
    target: str,
    *,
    max_paths: int,
    max_depth: int = _MAX_DEPTH,
) -> tuple[tuple[str, ...], ...]:
    relation = catalog.relations.get(start)
    if relation is None or not relation.alive:
        return ()
    paths: list[tuple[str, ...]] = []

    def walk(object_id: str, path: tuple[str, ...], visited: frozenset[str]) -> None:
        if len(paths) >= max_paths or len(path) > max_depth + 1:
            return
        if object_id == target:
            paths.append(path)
            return
        current = catalog.relations.get(object_id)
        if current is None or not current.alive:
            return
        for edge in current.dependencies:
            if _edge_status(edge, catalog) not in (_EDGE_VALID, _EDGE_RENAMED):
                continue
            if edge.target_id in visited:
                continue
            walk(
                edge.target_id,
                path + (edge.target_id,),
                visited | {edge.target_id},
            )

    walk(start, (start,), frozenset({start}))
    return tuple(paths)


def _collect_blockers(
    catalog: _Catalog,
    start: str,
    *,
    max_depth: int,
) -> list[tuple[str, str, str, str]]:
    blockers = []
    seen: set[str] = set()
    stack = [(start, 0)]
    while stack:
        object_id, depth = stack.pop()
        if object_id in seen or depth > max_depth:
            continue
        seen.add(object_id)
        relation = catalog.relations.get(object_id)
        if relation is None or not relation.alive:
            continue
        for edge in relation.dependencies:
            status = _edge_status(edge, catalog)
            if status == _EDGE_NAME_REUSE:
                blockers.append(
                    (relation.object_id, edge.display, _EDGE_NAME_REUSE, edge.target_id)
                )
            elif status == _EDGE_MISSING:
                blockers.append(
                    (relation.object_id, edge.display, _EDGE_MISSING, edge.target_id)
                )
            else:
                stack.append((edge.target_id, depth + 1))
    return blockers


def _renames_for_path(
    path: tuple[str, ...],
    catalog: _Catalog,
) -> tuple[tuple[str, str], ...]:
    renames: list[tuple[str, str]] = []
    for object_id in path:
        for pair in _renames_for(object_id, catalog):
            if pair not in renames:
                renames.append(pair)
    return tuple(renames)


def _renames_for(object_id: str, catalog: _Catalog) -> list[tuple[str, str]]:
    relation = catalog.relations.get(object_id)
    if relation is None:
        return []
    renames: list[tuple[str, str]] = []
    for pair in relation.rename_history:
        if pair not in renames:
            renames.append(pair)
    if relation.name != relation.origin_name and not any(
        pair[1] == relation.name for pair in renames
    ):
        renames.append((relation.origin_name, relation.name))
    return renames


def _record_rename_traces(catalog: _Catalog, findings: _Findings) -> None:
    for relation in catalog.relations.values():
        for old, new in relation.rename_history:
            findings.add(
                ("rename-trace", relation.object_id, old, new),
                Finding(
                    kind=FindingKind.RENAMED,
                    category=FindingCategory.TRACE,
                    message=f"{old!r} renamed to {new!r}; identity preserved",
                    severity="info",
                    object_id=relation.object_id,
                    name=old,
                    related_name=new,
                ),
            )


def _relation_views(catalog: _Catalog) -> tuple[RelationView, ...]:
    views = []
    for relation in catalog.relations.values():
        views.append(
            RelationView(
                object_id=relation.object_id,
                kind=relation.kind,
                name=relation.name,
                origin_name=relation.origin_name,
                origin=relation.origin,
                alive=relation.alive,
                dependencies=tuple(edge.display for edge in relation.dependencies),
                dependency_ids=tuple(edge.target_id for edge in relation.dependencies),
                rename_history=tuple(relation.rename_history),
                redefinition_count=relation.redefinition_count,
            )
        )
    return tuple(views)


# ---------------------------------------------------------------------------
# File helper and CLI
# ---------------------------------------------------------------------------


def review_files(
    declarations_path,
    freeze_path=None,
    migration_path=None,
    **kwargs,
) -> ReviewResult:
    """Read the three inputs from UTF-8 files and call :func:`review`."""

    declarations = _read_text(declarations_path)
    freeze = _read_text(freeze_path) if freeze_path else None
    migration = _read_text(migration_path) if migration_path else ""
    return review(declarations, freeze, migration, **kwargs)


def _read_text(path) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m sqlparse.review",
        description="Offline review of a planned view migration against frozen evidence.",
    )
    parser.add_argument("--declarations", required=True, help="baseline CREATE statements")
    parser.add_argument("--freeze", help="freeze list")
    parser.add_argument("--migration", help="planned migration statements")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--max-objects", type=int, default=_MAX_OBJECTS)
    parser.add_argument("--max-paths", type=int, default=_MAX_PATHS)
    parser.add_argument("--max-depth", type=int, default=_MAX_DEPTH)
    args = parser.parse_args(argv)

    result = review_files(
        args.declarations,
        args.freeze,
        args.migration,
        max_objects=args.max_objects,
        max_paths=args.max_paths,
        max_depth=args.max_depth,
    )
    print(result.to_json() if args.json else result.format())
    return 0 if result.safe else 1


if __name__ == "__main__":
    raise SystemExit(main())
