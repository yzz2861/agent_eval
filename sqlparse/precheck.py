#
# Copyright (C) 2009-2020 the sqlparse authors and contributors
# <see AUTHORS file>
#
# This module is part of python-sqlparse and is released under
# the BSD License: https://opensource.org/licenses/BSD-3-Clause

"""Offline privilege precheck for a small, documented migration subset.

This module is deliberately a parser and a simulator, not an executor.  It
reads ordinary migration statements, follows transaction control and
savepoints, and reports the privilege state that would remain after commit.
No database connection is opened and no SQL is sent anywhere.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import sqlparse
from sqlparse import tokens as T
from sqlparse.exceptions import PrecheckInputError

__all__ = [
    "ApprovedChange",
    "InitialObject",
    "PrecheckResult",
    "precheck",
    "precheck_migration",
]

DECISION_APPROVED = "approved"
DECISION_MANUAL_REVIEW = "manual_review"

_ACTIONS = frozenset({"grant", "revoke"})

_TABLE_PRIVILEGES = frozenset({
    "SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES",
    "TRIGGER",
})
_SEQUENCE_PRIVILEGES = frozenset({"USAGE", "SELECT", "UPDATE"})
_SCHEMA_PRIVILEGES = frozenset({"USAGE", "CREATE"})
_DATABASE_PRIVILEGES = frozenset({
    "CONNECT", "CREATE", "TEMPORARY", "TEMP",
})
_FUNCTION_PRIVILEGES = frozenset({"EXECUTE"})

_PRIVILEGES_BY_KIND = {
    "table": _TABLE_PRIVILEGES,
    "view": _TABLE_PRIVILEGES,
    "materialized view": _TABLE_PRIVILEGES,
    "sequence": _SEQUENCE_PRIVILEGES,
    "schema": _SCHEMA_PRIVILEGES,
    "database": _DATABASE_PRIVILEGES,
    "function": _FUNCTION_PRIVILEGES,
    "procedure": _FUNCTION_PRIVILEGES,
    "routine": _FUNCTION_PRIVILEGES,
}

_GRANTABLE_KINDS = {
    "TABLE": "table",
    "SEQUENCE": "sequence",
    "SCHEMA": "schema",
    "DATABASE": "database",
}

_ALL_PRIVILEGES = frozenset().union(*_PRIVILEGES_BY_KIND.values())

_PUNCTUATION = frozenset({",", ".", "(", ")", ";", "[", "]"})
_UNSUPPORTED_PRIVILEGES = frozenset({
    "SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES",
    "TRIGGER", "USAGE", "CREATE", "CONNECT", "TEMPORARY", "TEMP", "EXECUTE",
})


def _key(value: str | None) -> str:
    return (value or "").casefold()


def _qualified(schema: str | None, name: str) -> str:
    return f"{schema}.{name}" if schema else name


def _unquote_identifier(value: str) -> str:
    """Return the logical identifier, rejecting non-identifier tokens."""
    if not value:
        raise _SyntaxProblem("empty identifier")
    if value in _PUNCTUATION:
        raise _SyntaxProblem(f"expected an identifier, got {value!r}")
    if value[0] == '"' and value[-1:] == '"' and len(value) >= 2:
        return value[1:-1].replace('""', '"')
    if value[0] in "'`":
        raise _Unsupported(
            f"identifier {value!r} uses a quoting style outside the subset"
        )
    if value[0].isdigit():
        raise _SyntaxProblem(f"expected an identifier, got {value!r}")
    return value


class _SyntaxProblem(Exception):
    """The statement is malformed inside a form the precheck recognizes."""


class _Unsupported(Exception):
    """The statement is valid SQL but outside the documented subset."""


class _Failure(Exception):
    """A recognized statement cannot be applied to the catalog state."""


@dataclass(frozen=True)
class _Lexeme:
    value: str
    ttype: Any


@dataclass(frozen=True)
class _Command:
    kind: str
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class InitialObject:
    """An object and its privileges before the migration.

    ``object_id`` is the stable identity used by approvals and by the result.
    When omitted it defaults to the qualified initial name.  A later
    ``ALTER TABLE ... RENAME TO`` or ``SET SCHEMA`` changes the current name
    but never the ``object_id``.
    """

    name: str
    schema: str | None = None
    kind: str = "table"
    object_id: str | None = None
    privileges: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ApprovedChange:
    """One privilege change that has already been approved."""

    object_id: str
    grantee: str
    privilege: str
    action: str = "grant"


@dataclass(frozen=True)
class PrecheckResult:
    """Serializable result returned by :func:`precheck_migration`."""

    decision: str
    release_ok: bool
    summary: str
    status: str
    initial_objects: tuple[dict[str, Any], ...]
    post_commit_objects: tuple[dict[str, Any], ...] | None
    privilege_diff: dict[str, Any]
    statements: tuple[dict[str, Any], ...]
    uncertainties: tuple[dict[str, Any], ...]
    approved_changes: tuple[dict[str, Any], ...]
    approved_changes_not_applied: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "release_ok": self.release_ok,
            "summary": self.summary,
            "status": self.status,
            "initial_objects": list(self.initial_objects),
            "post_commit_objects": (
                None
                if self.post_commit_objects is None
                else list(self.post_commit_objects)
            ),
            "privilege_diff": dict(self.privilege_diff),
            "statements": list(self.statements),
            "uncertainties": list(self.uncertainties),
            "approved_changes": list(self.approved_changes),
            "approved_changes_not_applied": list(
                self.approved_changes_not_applied
            ),
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)


@dataclass
class _Object:
    object_id: str
    schema: str | None
    name: str
    kind: str
    privileges: dict[str, set[str]]

    def clone(self) -> _Object:
        return _Object(
            object_id=self.object_id,
            schema=self.schema,
            name=self.name,
            kind=self.kind,
            privileges={
                grantee: set(values)
                for grantee, values in self.privileges.items()
            },
        )

    @property
    def qualified_name(self) -> str:
        return _qualified(self.schema, self.name)


@dataclass
class _State:
    objects: dict[str, _Object]

    def clone(self) -> _State:
        return _State({
            object_key: obj.clone()
            for object_key, obj in self.objects.items()
        })


@dataclass
class _Savepoint:
    name: str
    statement_index: int
    state: _State


def _lexemes(statement: sqlparse.sql.Statement) -> list[_Lexeme]:
    result = []
    for token in statement.flatten():
        if token.is_whitespace:
            continue
        if token.ttype is not None and token.ttype in T.Comment:
            continue
        if token.value == ";":
            continue
        result.append(_Lexeme(token.value, token.ttype))
    return result


def _word(lexeme: _Lexeme) -> str:
    return lexeme.value.upper()


def _parse_identifier(tokens: list[_Lexeme], index: int) -> tuple[str, int]:
    if index >= len(tokens):
        raise _SyntaxProblem("expected an identifier at end of statement")
    return _unquote_identifier(tokens[index].value), index + 1


def _parse_qname(
    tokens: list[_Lexeme], index: int
) -> tuple[str | None, str, int]:
    first, index = _parse_identifier(tokens, index)
    if index < len(tokens) and tokens[index].value == ".":
        second, index = _parse_identifier(tokens, index + 1)
        if index < len(tokens) and tokens[index].value == ".":
            raise _Unsupported(
                "three-part object names are outside the precheck subset"
            )
        return first, second, index
    return None, first, index


def _parse_name_list(
    tokens: list[_Lexeme], index: int
) -> tuple[list[str], int]:
    names = []
    while True:
        name, index = _parse_identifier(tokens, index)
        names.append(name)
        if index < len(tokens) and tokens[index].value == ",":
            index += 1
            continue
        return names, index


def _parse_privilege_list(
    tokens: list[_Lexeme], index: int
) -> tuple[list[str], int]:
    privileges = []
    while True:
        if index >= len(tokens):
            raise _SyntaxProblem("expected a privilege list")
        word = _word(tokens[index])
        if word == "ALL":
            index += 1
            if index < len(tokens) and _word(tokens[index]) == "PRIVILEGES":
                index += 1
            privileges.append("ALL")
        elif word in _UNSUPPORTED_PRIVILEGES:
            privileges.append(word)
            index += 1
        else:
            raise _Unsupported(
                f"privilege {tokens[index].value!r} is outside the "
                "precheck subset"
            )
        if index < len(tokens) and tokens[index].value == ",":
            index += 1
            continue
        return privileges, index


def _expect_word(tokens: list[_Lexeme], index: int, word: str) -> int:
    if index >= len(tokens) or _word(tokens[index]) != word:
        actual = tokens[index].value if index < len(tokens) else "<end>"
        raise _SyntaxProblem(f"expected {word!r}, got {actual!r}")
    return index + 1


def _parse_object_kind(
    tokens: list[_Lexeme], index: int
) -> tuple[str | None, int]:
    if index < len(tokens) and _word(tokens[index]) in _GRANTABLE_KINDS:
        return _GRANTABLE_KINDS[_word(tokens[index])], index + 1
    return None, index


def _parse_grant(tokens: list[_Lexeme], *, revoke: bool) -> _Command:
    index = 1
    if revoke and index < len(tokens) and _word(tokens[index]) == "GRANT":
        if (
            index + 1 < len(tokens)
            and _word(tokens[index + 1]) == "OPTION"
        ):
            raise _Unsupported("REVOKE GRANT OPTION FOR is outside the subset")
    privileges, index = _parse_privilege_list(tokens, index)
    index = _expect_word(tokens, index, "ON")
    if index < len(tokens) and _word(tokens[index]) == "ALL":
        raise _Unsupported(
            "GRANT/REVOKE ... ON ALL ... is outside the precheck subset"
        )
    if index < len(tokens) and _word(tokens[index]) in {
        "FUNCTION", "PROCEDURE", "ROUTINE", "TYPE", "DOMAIN",
        "LANGUAGE", "TABLESPACE", "FOREIGN",
    }:
        raise _Unsupported(
            "grants on functions, types, languages, tablespaces and "
            "foreign objects are outside the precheck subset"
        )
    kind, index = _parse_object_kind(tokens, index)
    schema, name, index = _parse_qname(tokens, index)
    index = _expect_word(tokens, index, "FROM" if revoke else "TO")
    grantees, index = _parse_name_list(tokens, index)
    if index != len(tokens):
        remaining = " ".join(token.value for token in tokens[index:])
        raise _Unsupported(
            f"clause {remaining!r} is outside the precheck subset"
        )
    return _Command(
        "revoke" if revoke else "grant",
        {
            "privileges": privileges,
            "kind": kind,
            "schema": schema,
            "name": name,
            "grantees": grantees,
        },
    )


def _parse_rename(tokens: list[_Lexeme]) -> _Command:
    if len(tokens) < 2 or _word(tokens[1]) != "TABLE":
        raise _Unsupported("only ALTER TABLE renames are supported")
    index = 2
    if index < len(tokens) and _word(tokens[index]) == "ONLY":
        raise _Unsupported("ALTER TABLE ONLY is outside the precheck subset")
    schema, name, index = _parse_qname(tokens, index)
    if index >= len(tokens):
        raise _SyntaxProblem("expected RENAME or SET SCHEMA")
    action = _word(tokens[index])
    if action == "RENAME":
        index += 1
        if index >= len(tokens) or _word(tokens[index]) != "TO":
            raise _Unsupported(
                "only ALTER TABLE ... RENAME TO is supported; column, "
                "constraint and other renames are outside the subset"
            )
        new_name, index = _parse_identifier(tokens, index + 1)
        if index < len(tokens):
            raise _Unsupported("unexpected clause after RENAME TO")
        return _Command(
            "rename",
            {
                "schema": schema,
                "name": name,
                "new_name": new_name,
            },
        )
    if action == "SET":
        index += 1
        index = _expect_word(tokens, index, "SCHEMA")
        new_schema, index = _parse_identifier(tokens, index)
        if index < len(tokens):
            raise _Unsupported("unexpected clause after SET SCHEMA")
        return _Command(
            "set_schema",
            {
                "schema": schema,
                "name": name,
                "new_schema": new_schema,
            },
        )
    raise _Unsupported(
        "only ALTER TABLE ... RENAME TO and SET SCHEMA are supported"
    )


def _parse_transaction_command(
    tokens: list[_Lexeme], first: str
) -> _Command:
    length = len(tokens)
    if first in {"BEGIN", "START"}:
        if first == "START":
            if length != 2 or _word(tokens[1]) != "TRANSACTION":
                raise _Unsupported(
                    "only START TRANSACTION is supported for START"
                )
        elif length > 2 or (
            length == 2
            and _word(tokens[1]) not in {"WORK", "TRANSACTION"}
        ):
            raise _Unsupported(
                "BEGIN options are outside the precheck subset"
            )
        return _Command("begin")

    if first == "COMMIT":
        if length > 2 or (
            length == 2
            and _word(tokens[1]) not in {"WORK", "TRANSACTION"}
        ):
            raise _Unsupported(
                "COMMIT options such as AND CHAIN are outside the subset"
            )
        return _Command("commit")

    if first == "ROLLBACK":
        index = 1
        if index < length and _word(tokens[index]) == "WORK":
            index += 1
        if index == length:
            return _Command("rollback")
        index = _expect_word(tokens, index, "TO")
        if index < length and _word(tokens[index]) == "SAVEPOINT":
            index += 1
        name, index = _parse_identifier(tokens, index)
        if index != length:
            raise _Unsupported("unexpected clause after ROLLBACK TO SAVEPOINT")
        return _Command("rollback_to", {"name": name})

    if first == "SAVEPOINT":
        name, index = _parse_identifier(tokens, 1)
        if index != length:
            raise _Unsupported("unexpected clause after SAVEPOINT")
        return _Command("savepoint", {"name": name})

    if first == "RELEASE":
        index = 1
        if index < length and _word(tokens[index]) == "SAVEPOINT":
            index += 1
        name, index = _parse_identifier(tokens, index)
        if index != length:
            raise _Unsupported("unexpected clause after RELEASE SAVEPOINT")
        return _Command("release", {"name": name})

    raise _Unsupported(f"transaction command {first!r} is not supported")


def _parse_statement(statement: sqlparse.sql.Statement) -> _Command | None:
    tokens = _lexemes(statement)
    if not tokens:
        return None
    first = _word(tokens[0])
    if first in {"GRANT", "REVOKE"}:
        return _parse_grant(tokens, revoke=first == "REVOKE")
    if first == "ALTER":
        return _parse_rename(tokens)
    if first in {
        "BEGIN", "START", "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE",
    }:
        return _parse_transaction_command(tokens, first)
    raise _Unsupported(
        f"statement type {tokens[0].value!r} is outside the precheck subset"
    )


def _coerce_mapping(
    value: Any, label: str
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PrecheckInputError(f"{label} must be a mapping")
    return value


def _coerce_initial_object(value: Any) -> InitialObject:
    if isinstance(value, InitialObject):
        return value
    data = _coerce_mapping(value, "each initial object")
    name = data.get("name")
    if not isinstance(name, str) or not name:
        raise PrecheckInputError("initial object requires a non-empty 'name'")
    schema = data.get("schema")
    if schema is not None and not isinstance(schema, str):
        raise PrecheckInputError("initial object 'schema' must be a string")
    kind = data.get("kind", "table")
    if not isinstance(kind, str) or not kind:
        raise PrecheckInputError("initial object 'kind' must be a string")
    object_id = data.get("object_id")
    if object_id is not None and not isinstance(object_id, str):
        raise PrecheckInputError("initial object 'object_id' must be a string")
    privileges = data.get("privileges", {})
    if privileges is None:
        privileges = {}
    return InitialObject(
        name=name,
        schema=schema,
        kind=kind.casefold(),
        object_id=object_id,
        privileges=_coerce_mapping(privileges, "initial object privileges"),
    )


def _coerce_approved_change(value: Any) -> ApprovedChange:
    if isinstance(value, ApprovedChange):
        change = value
    else:
        data = _coerce_mapping(value, "each approved change")
        object_id = data.get("object_id")
        grantee = data.get("grantee")
        privilege = data.get("privilege")
        action = data.get("action", "grant")
        if not isinstance(object_id, str) or not object_id:
            raise PrecheckInputError(
                "approved change requires a non-empty 'object_id'"
            )
        if not isinstance(grantee, str) or not grantee:
            raise PrecheckInputError(
                "approved change requires a non-empty 'grantee'"
            )
        if not isinstance(privilege, str) or not privilege:
            raise PrecheckInputError(
                "approved change requires a non-empty 'privilege'"
            )
        if not isinstance(action, str):
            raise PrecheckInputError(
                "approved change 'action' must be a string"
            )
        change = ApprovedChange(
            object_id=object_id,
            grantee=grantee,
            privilege=privilege,
            action=action,
        )
    action = change.action.casefold()
    if action not in _ACTIONS:
        raise PrecheckInputError(
            f"approved change action must be one of {sorted(_ACTIONS)}"
        )
    return ApprovedChange(
        object_id=change.object_id,
        grantee=change.grantee,
        privilege=change.privilege.upper(),
        action=action,
    )


def _normalise_initial_privileges(
    privileges: Mapping[str, Any],
    kind: str,
) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for grantee, raw in privileges.items():
        if not isinstance(grantee, str) or not grantee:
            raise PrecheckInputError("privilege grantee must be a string")
        if isinstance(raw, str):
            values = [raw]
        else:
            try:
                values = list(raw)
            except TypeError as exc:
                raise PrecheckInputError(
                    f"privileges for {grantee!r} must be a string or list"
                ) from exc
        expanded: set[str] = set()
        for value in values:
            if not isinstance(value, str) or not value:
                raise PrecheckInputError(
                    f"privilege for {grantee!r} must be a string"
                )
            privilege = value.upper()
            allowed = _PRIVILEGES_BY_KIND.get(kind)
            if privilege == "ALL":
                if allowed is None:
                    raise PrecheckInputError(
                        f"cannot expand ALL for object kind {kind!r}"
                    )
                expanded.update(allowed)
                continue
            if privilege not in _ALL_PRIVILEGES:
                raise PrecheckInputError(
                    f"unknown initial privilege {privilege!r}"
                )
            if allowed is not None and privilege not in allowed:
                raise PrecheckInputError(
                    f"privilege {privilege!r} is not valid for "
                    f"object kind {kind!r}"
                )
            expanded.add(privilege)
        if expanded:
            result[_key(grantee)] = expanded
    return result


def _make_initial_state(
    initial_objects: Iterable[InitialObject | Mapping[str, Any]],
) -> tuple[_State, dict[str, str], dict[str, set[str]]]:
    objects: dict[str, _Object] = {}
    names: dict[str, str] = {}
    aliases: dict[str, set[str]] = {}
    for raw in initial_objects:
        item = _coerce_initial_object(raw)
        object_id = item.object_id or _qualified(item.schema, item.name)
        object_key = _key(object_id)
        if object_key in objects:
            raise PrecheckInputError(
                f"duplicate initial object_id {object_id!r}"
            )
        name_key = _key(_qualified(item.schema, item.name))
        if name_key in names:
            raise PrecheckInputError(
                f"duplicate initial object name {item.name!r}"
            )
        kind = item.kind.casefold()
        object_ = _Object(
            object_id=object_id,
            schema=item.schema,
            name=item.name,
            kind=kind,
            privileges=_normalise_initial_privileges(item.privileges, kind),
        )
        objects[object_key] = object_
        names[name_key] = object_key
        for alias in {
            object_id,
            _qualified(item.schema, item.name),
            item.name,
        }:
            aliases.setdefault(_key(alias), set()).add(object_key)
    return _State(objects), names, aliases


def _find_object(
    state: _State,
    schema: str | None,
    name: str,
    kind: str | None,
) -> _Object:
    matches = []
    for object_ in state.objects.values():
        if _key(object_.name) != _key(name):
            continue
        if schema is not None and object_.schema is not None:
            if _key(object_.schema) != _key(schema):
                continue
        if kind is not None and object_.kind != kind:
            continue
        matches.append(object_)
    if not matches:
        expected = _qualified(schema, name)
        raise _Failure(
            f"object {expected!r} is not present in the precheck catalog"
        )
    if len(matches) > 1:
        raise _Failure(
            f"object name {name!r} is ambiguous; qualify it with a schema"
        )
    return matches[0]


def _expanded_privileges(object_: _Object, privileges: list[str]) -> list[str]:
    result: list[str] = []
    for privilege in privileges:
        if privilege == "ALL":
            allowed = _PRIVILEGES_BY_KIND.get(object_.kind)
            if allowed is None:
                raise _Unsupported(
                    f"ALL is not defined for object kind {object_.kind!r}"
                )
            result.extend(sorted(allowed))
        else:
            result.append(privilege)
    allowed = _PRIVILEGES_BY_KIND.get(object_.kind)
    if allowed is not None:
        invalid = sorted(set(result) - set(allowed))
        if invalid:
            raise _Failure(
                f"privilege(s) {', '.join(invalid)} are not valid for "
                f"object kind {object_.kind!r}"
            )
    return result


def _object_ref(object_: _Object) -> dict[str, Any]:
    return {
        "object_id": object_.object_id,
        "schema": object_.schema,
        "name": object_.name,
    }


class _Simulator:
    def __init__(
        self,
        initial_state: _State,
        aliases: dict[str, set[str]],
        approved_changes: list[ApprovedChange],
    ):
        self.initial = initial_state
        self.committed = initial_state.clone()
        self.working: _State | None = None
        self.aliases = {
            alias: set(object_keys)
            for alias, object_keys in aliases.items()
        }
        self.approved_changes = approved_changes
        self.role_names: dict[str, str] = {}
        self.tx_state = "none"
        self.tx_start_index = 0
        self.savepoints: list[_Savepoint] = []
        self.records: list[dict[str, Any]] = []
        self.uncertainties: list[dict[str, Any]] = []
        self.halted: str | None = None
        self.final_state_known = True
        self.record_schema()

    def record_schema(self) -> None:
        for object_ in self.initial.objects.values():
            for grantee in object_.privileges:
                self.role_names.setdefault(grantee, grantee)

    @property
    def state(self) -> _State:
        return self.working if self.working is not None else self.committed

    def _add_alias(self, name: str, object_key: str) -> None:
        self.aliases.setdefault(_key(name), set()).add(object_key)

    def _role_name(self, grantee: str) -> str:
        key = _key(grantee)
        self.role_names.setdefault(key, grantee)
        return key

    def _uncertainty(
        self,
        code: str,
        message: str,
        statement_index: int | None,
        affected: list[str],
    ) -> None:
        self.uncertainties.append({
            "code": code,
            "statement_index": statement_index,
            "message": message,
            "affected_conclusions": affected,
        })

    def _record(
        self,
        index: int,
        sql: str,
        kind: str,
        status: str,
        reason: str,
        *,
        effects: list[dict[str, Any]] | None = None,
        transaction: str = "autocommit",
    ) -> dict[str, Any]:
        record = {
            "index": index,
            "sql": sql,
            "kind": kind,
            "status": status,
            "reason": reason,
            "transaction": transaction,
            "effects": effects or [],
        }
        self.records.append(record)
        return record

    def _mark_rolled_back(self, floor: int, reason: str) -> None:
        for record in self.records:
            if record["index"] <= floor:
                continue
            if record["status"] == "uncommitted":
                record["status"] = "rolled_back"
                record["reason"] = f"{record['reason']} {reason}"

    def _mark_committed(self) -> None:
        for record in self.records:
            if record["status"] == "uncommitted":
                record["status"] = "committed"

    def _set_unknown(self, reason: str, index: int) -> None:
        self.tx_state = "unknown"
        self.final_state_known = False
        self._uncertainty(
            "unsupported_syntax",
            reason,
            index,
            [
                "statement_effect",
                "transaction_outcome",
                "post_commit_privileges",
                "privilege_diff",
                "decision",
            ],
        )

    def _fail(
        self,
        index: int,
        sql: str,
        kind: str,
        message: str,
        *,
        code: str = "statement_failed",
    ) -> None:
        transaction = "explicit" if self.tx_state == "active" else "autocommit"
        if self.tx_state == "active":
            self.tx_state = "aborted"
            affected = [
                "statement_effect",
                "transaction_outcome",
                "post_commit_privileges",
                "privilege_diff",
                "decision",
            ]
        else:
            self.halted = message
            affected = [
                "statement_effect",
                "remaining_migration",
                "decision",
            ]
        self._record(
            index,
            sql,
            kind,
            "rejected",
            message,
            transaction=transaction,
        )
        self._uncertainty(code, message, index, affected)

    def _skip(self, index: int, sql: str, reason: str) -> None:
        self._record(
            index,
            sql,
            "skipped",
            "skipped",
            reason,
            transaction="aborted transaction",
        )

    def _unknown(self, index: int, sql: str, reason: str) -> None:
        self._record(
            index,
            sql,
            "unknown",
            "unknown",
            reason,
            transaction="unknown transaction",
        )

    def run(self, sql: str) -> None:
        statements = sqlparse.parse(sql)
        for index, statement in enumerate(statements, start=1):
            text = str(statement).strip()
            if not text:
                continue
            if self.halted is not None:
                self._record(
                    index,
                    text,
                    "not_executed",
                    "not_executed",
                    f"Not executed because the migration stopped earlier: "
                    f"{self.halted}",
                    transaction="not executed",
                )
                continue
            if self.tx_state == "unknown":
                self._unknown(
                    index,
                    text,
                    "Not simulated because an earlier statement made the "
                    "transaction outcome unknown.",
                )
                continue
            if self.tx_state == "aborted":
                tokens = _lexemes(statement)
                first = _word(tokens[0]) if tokens else ""
                if first not in {"COMMIT", "ROLLBACK"}:
                    self._skip(
                        index,
                        text,
                        "Skipped because the transaction is aborted; the "
                        "server would reject this statement until rollback.",
                    )
                    continue
            self._dispatch(statement, index, text)

    def _dispatch(
        self,
        statement: sqlparse.sql.Statement,
        index: int,
        text: str,
    ) -> None:
        try:
            command = _parse_statement(statement)
        except _Unsupported as exc:
            transaction = (
                "explicit" if self.tx_state == "active" else "autocommit"
            )
            self._set_unknown(str(exc), index)
            self._record(
                index,
                text,
                "unsupported",
                "unsupported",
                str(exc),
                transaction=transaction,
            )
            return
        except _SyntaxProblem as exc:
            self._fail(
                index,
                text,
                "syntax_error",
                f"Unsupported or malformed syntax: {exc}",
                code="syntax_error",
            )
            return
        if command is None:
            return
        handler = getattr(self, f"_do_{command.kind}", None)
        if handler is None:
            self._set_unknown(
                f"statement kind {command.kind!r} is not implemented", index
            )
            self._record(
                index, text, command.kind, "unsupported",
                f"statement kind {command.kind!r} is not implemented",
            )
            return
        handler(command.payload, index, text)

    def _do_begin(
        self, payload: dict[str, Any], index: int, text: str
    ) -> None:
        if self.tx_state == "none":
            self.working = self.committed.clone()
            self.tx_state = "active"
            self.tx_start_index = index
            self.savepoints = []
            self._record(
                index,
                text,
                "begin",
                "applied",
                "Opened an explicit transaction.",
                transaction="none -> explicit",
            )
            return
        self._record(
            index,
            text,
            "begin",
            "no_op",
            "BEGIN inside an existing transaction is a no-op warning in "
            "PostgreSQL; no nested transaction is created.",
            transaction="explicit",
        )

    def _do_commit(
        self, payload: dict[str, Any], index: int, text: str
    ) -> None:
        if self.tx_state == "none":
            self._record(
                index,
                text,
                "commit",
                "no_op",
                "COMMIT outside a transaction is a no-op warning.",
            )
            return
        if self.tx_state == "active":
            self.committed = self.working.clone()  # type: ignore[union-attr]
            self._mark_committed()
            self.working = None
            self.savepoints = []
            self.tx_state = "none"
            self.tx_start_index = 0
            self._record(
                index,
                text,
                "commit",
                "applied",
                "Committed the transaction; all uncommitted privilege and "
                "rename effects became final.",
                transaction="explicit",
            )
            return
        if self.tx_state == "aborted":
            self.working = None
            self.savepoints = []
            self.tx_state = "none"
            self._mark_rolled_back(
                self.tx_start_index,
                "Discarded because COMMIT in a failed transaction behaves "
                "as ROLLBACK.",
            )
            self.tx_start_index = 0
            self._record(
                index,
                text,
                "commit",
                "applied",
                "COMMIT in a failed transaction rolled back the whole "
                "transaction.",
                transaction="aborted -> none",
            )

    def _do_rollback(
        self, payload: dict[str, Any], index: int, text: str
    ) -> None:
        if self.tx_state == "none":
            self._record(
                index,
                text,
                "rollback",
                "no_op",
                "ROLLBACK outside a transaction is a no-op warning.",
            )
            return
        self.working = None
        self.savepoints = []
        self.tx_state = "none"
        self._mark_rolled_back(
            self.tx_start_index,
            "Discarded by ROLLBACK.",
        )
        self.tx_start_index = 0
        self._record(
            index,
            text,
            "rollback",
            "applied",
            "Rolled back the transaction and discarded all uncommitted "
            "privilege and rename effects.",
            transaction="explicit -> none",
        )

    def _do_savepoint(
        self, payload: dict[str, Any], index: int, text: str
    ) -> None:
        name = payload["name"]
        if self.tx_state == "none":
            self._fail(
                index,
                text,
                "savepoint",
                f"SAVEPOINT {name!r} outside a transaction is invalid.",
                code="transaction_failed",
            )
            return
        self.savepoints.append(
            _Savepoint(name=name, statement_index=index,
                       state=self.working.clone())  # type: ignore[union-attr]
        )
        self._record(
            index,
            text,
            "savepoint",
            "applied",
            f"Created savepoint {name!r}; it records both privilege grants "
            "and object names.",
            transaction="explicit",
        )

    def _find_savepoint(self, name: str) -> _Savepoint | None:
        for savepoint in reversed(self.savepoints):
            if _key(savepoint.name) == _key(name):
                return savepoint
        return None

    def _do_rollback_to(
        self, payload: dict[str, Any], index: int, text: str
    ) -> None:
        name = payload["name"]
        if self.tx_state == "none":
            self._fail(
                index,
                text,
                "rollback_to",
                f"ROLLBACK TO SAVEPOINT {name!r} outside a transaction is "
                "invalid.",
                code="transaction_failed",
            )
            return
        savepoint = self._find_savepoint(name)
        if savepoint is None:
            self._fail(
                index,
                text,
                "rollback_to",
                f"Savepoint {name!r} does not exist in the current "
                "transaction.",
                code="transaction_failed",
            )
            return
        self.working = savepoint.state.clone()
        self.savepoints = self.savepoints[
            : self.savepoints.index(savepoint) + 1
        ]
        self._mark_rolled_back(
            savepoint.statement_index,
            f"Rolled back by statement {index} "
            f"(ROLLBACK TO SAVEPOINT {name}).",
        )
        self.tx_state = "active"
        self._record(
            index,
            text,
            "rollback_to",
            "applied",
            f"Restored the state captured by savepoint {name!r}; effects "
            "and renames after that savepoint were discarded.",
            transaction="explicit",
        )

    def _do_release(
        self, payload: dict[str, Any], index: int, text: str
    ) -> None:
        name = payload["name"]
        if self.tx_state == "none":
            self._fail(
                index,
                text,
                "release",
                f"RELEASE SAVEPOINT {name!r} outside a transaction is "
                "invalid.",
                code="transaction_failed",
            )
            return
        savepoint = self._find_savepoint(name)
        if savepoint is None:
            self._fail(
                index,
                text,
                "release",
                f"Savepoint {name!r} does not exist in the current "
                "transaction.",
                code="transaction_failed",
            )
            return
        self.savepoints = self.savepoints[
            : self.savepoints.index(savepoint)
        ]
        self._record(
            index,
            text,
            "release",
            "applied",
            f"Released savepoint {name!r}; effects remain part of the "
            "transaction and can still be committed or rolled back.",
            transaction="explicit",
        )

    def _do_grant(
        self, payload: dict[str, Any], index: int, text: str
    ) -> None:
        self._apply_privilege(payload, index, text, grant=True)

    def _do_revoke(
        self, payload: dict[str, Any], index: int, text: str
    ) -> None:
        self._apply_privilege(payload, index, text, grant=False)

    def _apply_privilege(
        self,
        payload: dict[str, Any],
        index: int,
        text: str,
        *,
        grant: bool,
    ) -> None:
        target = self.state
        try:
            object_ = _find_object(
                target,
                payload["schema"],
                payload["name"],
                payload["kind"],
            )
            privileges = _expanded_privileges(
                object_, payload["privileges"]
            )
        except _Failure as exc:
            self._fail(
                index,
                text,
                "grant" if grant else "revoke",
                str(exc),
                code="transaction_failed",
            )
            return
        except _Unsupported as exc:
            transaction = (
                "explicit" if self.tx_state == "active" else "autocommit"
            )
            self._set_unknown(str(exc), index)
            self._record(
                index,
                text,
                "grant" if grant else "revoke",
                "unsupported",
                str(exc),
                transaction=transaction,
            )
            return

        effects: list[dict[str, Any]] = []
        no_ops = 0
        for grantee in payload["grantees"]:
            grantee_key = self._role_name(grantee)
            held = object_.privileges.setdefault(grantee_key, set())
            for privilege in privileges:
                if grant and privilege not in held:
                    held.add(privilege)
                    effects.append({
                        "action": "grant",
                        **_object_ref(object_),
                        "grantee": self.role_names[grantee_key],
                        "privilege": privilege,
                    })
                elif not grant and privilege in held:
                    held.remove(privilege)
                    effects.append({
                        "action": "revoke",
                        **_object_ref(object_),
                        "grantee": self.role_names[grantee_key],
                        "privilege": privilege,
                    })
                else:
                    no_ops += 1
            if not held:
                object_.privileges.pop(grantee_key, None)

        verb = "Granted" if grant else "Revoked"
        prep = "to" if grant else "from"
        names = ", ".join(self.role_names[_key(g)] for g in payload["grantees"])
        if effects:
            privilege_text = ", ".join(sorted({p["privilege"] for p in effects}))
            reason = (
                f"{verb} {privilege_text} on {object_.qualified_name} "
                f"({object_.object_id}) {prep} {names}; "
                f"{len(effects)} privilege change(s)"
            )
            if no_ops:
                reason += f", {no_ops} already in the requested state"
            reason += "."
            status = "committed" if self.tx_state == "none" else "uncommitted"
        else:
            state_word = "already held" if grant else "not held"
            reason = (
                f"No privilege change on {object_.qualified_name} "
                f"({object_.object_id}) for {names}: every requested "
                f"privilege was {state_word}."
            )
            status = "no_op"
        self._record(
            index,
            text,
            "grant" if grant else "revoke",
            status,
            reason,
            effects=effects,
            transaction=(
                "autocommit" if self.tx_state == "none" else "explicit"
            ),
        )

    def _do_rename(
        self, payload: dict[str, Any], index: int, text: str
    ) -> None:
        self._apply_rename(payload, index, text, set_schema=False)

    def _do_set_schema(
        self, payload: dict[str, Any], index: int, text: str
    ) -> None:
        self._apply_rename(payload, index, text, set_schema=True)

    def _apply_rename(
        self,
        payload: dict[str, Any],
        index: int,
        text: str,
        *,
        set_schema: bool,
    ) -> None:
        target = self.state
        try:
            object_ = _find_object(
                target,
                payload["schema"],
                payload["name"],
                None,
            )
        except _Failure as exc:
            self._fail(
                index, text, "rename", str(exc), code="transaction_failed"
            )
            return
        if object_.kind != "table":
            self._fail(
                index,
                text,
                "rename",
                f"Object {object_.qualified_name!r} is a {object_.kind}, "
                "not a table.",
                code="transaction_failed",
            )
            return
        old_name = object_.qualified_name
        new_name = payload.get("new_name")
        new_schema = payload.get("new_schema")
        target_schema = new_schema if set_schema else object_.schema
        target_name = new_name if new_name is not None else object_.name
        for other_key, other in target.objects.items():
            if other_key == _key(object_.object_id):
                continue
            if (
                _key(other.schema) == _key(target_schema)
                and _key(other.name) == _key(target_name)
            ):
                self._fail(
                    index,
                    text,
                    "rename",
                    f"Cannot rename to {_qualified(target_schema, target_name)!r}; "
                    "another catalog object already has that name.",
                    code="transaction_failed",
                )
                return
        if (
            _key(target_schema) == _key(object_.schema)
            and _key(target_name) == _key(object_.name)
        ):
            self._record(
                index,
                text,
                "rename",
                "no_op",
                f"{old_name} already has the requested name and schema.",
            )
            return
        if set_schema:
            object_.schema = target_schema
        else:
            object_.name = target_name
        self._add_alias(_qualified(object_.schema, object_.name),
                        _key(object_.object_id))
        self._add_alias(object_.name, _key(object_.object_id))
        effect = {
            "action": "set_schema" if set_schema else "rename",
            "object_id": object_.object_id,
            "from": old_name,
            "to": object_.qualified_name,
        }
        status = "committed" if self.tx_state == "none" else "uncommitted"
        self._record(
            index,
            text,
            "set_schema" if set_schema else "rename",
            status,
            f"Changed {old_name} to {object_.qualified_name}; stable "
            f"object identity {object_.object_id} is preserved.",
            effects=[effect],
            transaction=(
                "autocommit" if self.tx_state == "none" else "explicit"
            ),
        )

    def _resolve_approvals(self) -> list[dict[str, Any]]:
        resolved = []
        for change in self.approved_changes:
            object_keys = self.aliases.get(_key(change.object_id), set())
            if not object_keys:
                raise PrecheckInputError(
                    f"approved change references unknown object "
                    f"{change.object_id!r}"
                )
            if len(object_keys) > 1:
                raise PrecheckInputError(
                    f"approved change object {change.object_id!r} is "
                    "ambiguous; use object_id"
                )
            object_key = next(iter(object_keys))
            object_ = self.committed.objects.get(object_key)
            if object_ is None:
                object_ = self.initial.objects[object_key]
            resolved.append({
                "object_id": object_.object_id,
                "object_key": object_key,
                "schema": object_.schema,
                "name": object_.name,
                "grantee": self.role_names.get(
                    _key(change.grantee), change.grantee
                ),
                "grantee_key": _key(change.grantee),
                "privilege": change.privilege,
                "action": change.action,
            })
        return resolved

    def _object_json(self, object_: _Object) -> dict[str, Any]:
        privileges = {}
        for grantee_key in sorted(object_.privileges):
            values = object_.privileges[grantee_key]
            if values:
                privileges[self.role_names.get(grantee_key, grantee_key)] = (
                    sorted(values)
                )
        return {
            "object_id": object_.object_id,
            "schema": object_.schema,
            "name": object_.name,
            "kind": object_.kind,
            "privileges": privileges,
        }

    def _state_json(self, state: _State) -> list[dict[str, Any]]:
        return [
            self._object_json(state.objects[key])
            for key in sorted(state.objects)
        ]

    def _diff(
        self, resolved_approvals: list[dict[str, Any]]
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        if not self.final_state_known:
            affected = sorted({
                uncertainty["statement_index"]
                for uncertainty in self.uncertainties
                if uncertainty["statement_index"] is not None
            })
            return ({
                "status": "unknown",
                "added": [],
                "removed": [],
                "approved": [],
                "unapproved": [],
                "affected_by_statement(s)": affected,
            }, [])

        added = []
        removed = []
        for object_key in sorted(self.committed.objects):
            object_ = self.committed.objects[object_key]
            initial = self.initial.objects[object_key]
            initial_privs = {
                (grantee, privilege)
                for grantee, values in initial.privileges.items()
                for privilege in values
            }
            final_privs = {
                (grantee, privilege)
                for grantee, values in object_.privileges.items()
                for privilege in values
            }
            for grantee, privilege in sorted(final_privs - initial_privs):
                added.append({
                    "object_id": object_.object_id,
                    "schema": object_.schema,
                    "object_name": object_.name,
                    "grantee": self.role_names.get(grantee, grantee),
                    "grantee_key": grantee,
                    "privilege": privilege,
                    "action": "grant",
                    "approved": self._is_approved(
                        object_key, grantee, "grant", privilege,
                        resolved_approvals,
                    ),
                })
            for grantee, privilege in sorted(initial_privs - final_privs):
                removed.append({
                    "object_id": object_.object_id,
                    "schema": object_.schema,
                    "object_name": object_.name,
                    "grantee": self.role_names.get(grantee, grantee),
                    "grantee_key": grantee,
                    "privilege": privilege,
                    "action": "revoke",
                    "approved": self._is_approved(
                        object_key, grantee, "revoke", privilege,
                        resolved_approvals,
                    ),
                })
        changes = added + removed
        unapproved = [item for item in changes if not item["approved"]]
        approved = [item for item in changes if item["approved"]]
        return ({
            "status": "known",
            "added": added,
            "removed": removed,
            "approved": approved,
            "unapproved": unapproved,
        }, unapproved)

    @staticmethod
    def _is_approved(
        object_key: str,
        grantee_key: str,
        action: str,
        privilege: str,
        resolved_approvals: list[dict[str, Any]],
    ) -> bool:
        for approval in resolved_approvals:
            if approval["object_key"] != object_key:
                continue
            if approval["grantee_key"] != grantee_key:
                continue
            if approval["action"] != action:
                continue
            if approval["privilege"] in {"ALL", "*"}:
                return True
            if approval["privilege"] == privilege:
                return True
        return False

    def _unapplied_approvals(
        self,
        resolved_approvals: list[dict[str, Any]],
        diff: dict[str, Any],
    ) -> list[dict[str, Any]]:
        if diff["status"] != "known":
            return []
        actual = [
            (
                item["object_id"],
                item["grantee_key"],
                item["action"],
                item["privilege"],
            )
            for item in diff["added"] + diff["removed"]
        ]
        result = []
        for approval in resolved_approvals:
            if approval["privilege"] in {"ALL", "*"}:
                matched = any(
                    item[0] == approval["object_id"]
                    and item[1] == approval["grantee_key"]
                    and item[2] == approval["action"]
                    for item in actual
                )
            else:
                matched = (
                    approval["object_id"],
                    approval["grantee_key"],
                    approval["action"],
                    approval["privilege"],
                ) in actual
            if not matched:
                result.append({
                    "object_id": approval["object_id"],
                    "grantee": approval["grantee"],
                    "privilege": approval["privilege"],
                    "action": approval["action"],
                })
        return result

    def _finish_open_transaction(self) -> None:
        if self.tx_state == "active":
            self.final_state_known = False
            self._uncertainty(
                "open_transaction",
                "The migration ends with an open transaction. Without an "
                "explicit COMMIT, the post-commit privilege state cannot be "
                "determined by this offline precheck.",
                self.tx_start_index,
                [
                    "post_commit_privileges",
                    "privilege_diff",
                    "decision",
                ],
            )
        elif self.tx_state == "aborted":
            self.final_state_known = False
            self._uncertainty(
                "failed_transaction_not_closed",
                "The migration ends with a failed, still-open transaction; "
                "the final commit/rollback outcome is unknown.",
                self.tx_start_index,
                [
                    "post_commit_privileges",
                    "privilege_diff",
                    "decision",
                ],
            )

    def result(self) -> PrecheckResult:
        self._finish_open_transaction()
        resolved_approvals = self._resolve_approvals()
        diff, unapproved = self._diff(resolved_approvals)
        unapplied = self._unapplied_approvals(
            resolved_approvals, diff
        )
        has_error = any(
            record["status"] in {
                "rejected", "unsupported", "unknown", "not_executed",
            }
            for record in self.records
        )
        decision = (
            DECISION_APPROVED
            if self.final_state_known and not unapproved and not has_error
            and not self.uncertainties
            else DECISION_MANUAL_REVIEW
        )
        if decision == DECISION_APPROVED:
            summary = (
                "Approved: the post-commit privilege diff is fully known "
                "and every privilege change matches the approved allowlist."
            )
        else:
            reasons = []
            if not self.final_state_known:
                reasons.append("final state unknown")
            if unapproved:
                reasons.append(
                    f"{len(unapproved)} unapproved privilege change(s)"
                )
            if has_error:
                reasons.append("one or more statements failed or are "
                               "unsupported")
            if self.uncertainties and not reasons:
                reasons.append("uncertain transaction outcome")
            summary = "Manual review required: " + "; ".join(reasons) + "."

        return PrecheckResult(
            decision=decision,
            release_ok=decision == DECISION_APPROVED,
            summary=summary,
            status="known" if self.final_state_known else "unknown",
            initial_objects=tuple(self._state_json(self.initial)),
            post_commit_objects=(
                tuple(self._state_json(self.committed))
                if self.final_state_known
                else None
            ),
            privilege_diff=diff,
            statements=tuple(self.records),
            uncertainties=tuple(self.uncertainties),
            approved_changes=tuple(
                {
                    "object_id": approval["object_id"],
                    "grantee": approval["grantee"],
                    "privilege": approval["privilege"],
                    "action": approval["action"],
                    "matched": (
                        None
                        if diff["status"] != "known"
                        else not any(
                            item["object_id"] == approval["object_id"]
                            and item["grantee"] == approval["grantee"]
                            and item["privilege"] == approval["privilege"]
                            and item["action"] == approval["action"]
                            for item in unapplied
                        )
                    ),
                }
                for approval in resolved_approvals
            ),
            approved_changes_not_applied=tuple(unapplied),
        )


def precheck_migration(
    sql: str,
    initial_objects: Iterable[InitialObject | Mapping[str, Any]],
    approved_changes: Iterable[ApprovedChange | Mapping[str, Any]] = (),
) -> PrecheckResult:
    """Statically precheck privilege effects of a migration.

    The input is parsed with :func:`sqlparse.parse`; no SQL is executed.  The
    supported subset is documented in ``docs/source/precheck.rst``.  A
    statement outside that subset does not get a guessed effect: it makes the
    affected post-commit conclusions unknown and forces manual review.
    """
    if not isinstance(sql, str):
        raise PrecheckInputError("sql must be a string")
    initial_state, _names, aliases = _make_initial_state(initial_objects)
    approvals = [
        _coerce_approved_change(item)
        for item in approved_changes
    ]
    simulator = _Simulator(initial_state, aliases, approvals)
    simulator.run(sql)
    return simulator.result()


precheck = precheck_migration


def _text_report(result: PrecheckResult) -> str:
    lines = [
        f"DECISION: {result.decision.upper()}",
        f"STATUS:   {result.status}",
        result.summary,
        "",
    ]
    diff = result.privilege_diff
    lines.append(f"Privilege diff ({diff['status']}):")
    changes = diff.get("added", []) + diff.get("removed", [])
    if not changes:
        lines.append("  (none)")
    for change in changes:
        sign = "+" if change["action"] == "grant" else "-"
        approval = "approved" if change["approved"] else "UNAPPROVED"
        lines.append(
            f"  {sign} {change['action']} {change['privilege']} on "
            f"{change['object_name']} (object_id={change['object_id']}) "
            f"{'to' if change['action'] == 'grant' else 'from'} "
            f"{change['grantee']} [{approval}]"
        )
    lines.append("")
    lines.append("Statements:")
    for record in result.statements:
        lines.append(
            f"  {record['index']}. [{record['status']}] {record['sql']}"
        )
        lines.append(f"     {record['reason']}")
    if result.uncertainties:
        lines.append("")
        lines.append("Uncertainties:")
        for uncertainty in result.uncertainties:
            lines.append(
                f"  - {uncertainty['code']} at statement "
                f"{uncertainty['statement_index']}: "
                f"{uncertainty['message']}"
            )
            lines.append(
                "    affected: "
                + ", ".join(uncertainty["affected_conclusions"])
            )
    return "\n".join(lines) + "\n"


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sqlparse-precheck",
        description=(
            "Offline privilege precheck for a small migration subset. "
            "This only parses SQL; it never connects to a database."
        ),
    )
    parser.add_argument(
        "migration",
        help="migration file to inspect, or '-' for stdin",
    )
    parser.add_argument(
        "--state",
        required=True,
        help=(
            "JSON file with 'initial_objects' and optional "
            "'approved_changes'"
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the full result as JSON instead of a text report",
    )
    parser.add_argument(
        "--output",
        help="write the report to this file instead of stdout",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = create_parser().parse_args(argv)
    try:
        state_data = json.loads(Path(args.state).read_text(encoding="utf-8"))
        if not isinstance(state_data, Mapping):
            raise PrecheckInputError("state file must contain a JSON object")
        initial_objects = state_data.get("initial_objects")
        if not isinstance(initial_objects, list):
            raise PrecheckInputError(
                "state file requires an 'initial_objects' array"
            )
        approved_changes = state_data.get("approved_changes", [])
        if not isinstance(approved_changes, list):
            raise PrecheckInputError(
                "'approved_changes' must be an array"
            )
        if args.migration == "-":
            sql_text = sys.stdin.read()
        else:
            sql_text = Path(args.migration).read_text(encoding="utf-8")
        result = precheck_migration(
            sql_text,
            initial_objects,
            approved_changes,
        )
    except (OSError, json.JSONDecodeError, PrecheckInputError) as exc:
        sys.stderr.write(f"[ERROR] {exc}\n")
        return 2
    output = result.to_json() if args.json else _text_report(result)
    if args.output:
        try:
            Path(args.output).write_text(output, encoding="utf-8")
        except OSError as exc:
            sys.stderr.write(f"[ERROR] {exc}\n")
            return 2
    else:
        sys.stdout.write(output)
    return 0 if result.release_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
