"""Data-loss risk inspection for migration operation trees.

The audit phase walks the in-memory tree of
:class:`~alembic.operations.ops.MigrateOperation` objects that is
produced by autogenerate (or assembled by hand), rather than scanning rendered
migration source code.  It reports destructive operations such as
``drop_table`` and ``drop_column`` (including those
nested inside batch / :class:`.ModifyTableOps` containers) and
flags potentially data-losing column type changes.

Column type narrowing is delegated to a pluggable *dialect type policy* and may
be further overridden with a user supplied callback.  When there is not enough
type information to make a determination, the finding is reported as
:attr:`.Severity.UNKNOWN` instead of being silently treated as
safe.

.. versionadded:: 1.21.0

"""

from __future__ import annotations

from collections.abc import Callable
from collections.abc import Iterator
from collections.abc import Sequence
from dataclasses import dataclass
from dataclasses import field
import enum
import json
import re
from typing import Any
from typing import cast
from typing import TYPE_CHECKING

from sqlalchemy import types as sqltypes

from . import ops
from .. import util

if TYPE_CHECKING:
    from sqlalchemy.sql.type_api import TypeEngine

    from .ops import MigrateOperation


class Severity(enum.Enum):
    """Severity level of an :class:`.AuditFinding`.

    Levels are ordered from least to most severe; the ``UNKNOWN``
    level indicates an operation which *may* lose data but cannot be classified
    with the information available.  It is intentionally **not** equivalent to
    "safe".

    """

    INFO = "info"
    WARNING = "warning"
    UNKNOWN = "unknown"
    RISK = "risk"

    def __lt__(self, other: "Severity") -> bool:  # pragma: no cover - trivial
        return _SEVERITY_ORDER[self] < _SEVERITY_ORDER[other]

    def __le__(self, other: "Severity") -> bool:  # pragma: no cover - trivial
        return _SEVERITY_ORDER[self] <= _SEVERITY_ORDER[other]

    def __gt__(self, other: "Severity") -> bool:  # pragma: no cover - trivial
        return _SEVERITY_ORDER[self] > _SEVERITY_ORDER[other]

    def __ge__(self, other: "Severity") -> bool:  # pragma: no cover - trivial
        return _SEVERITY_ORDER[self] >= _SEVERITY_ORDER[other]


_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.WARNING: 1,
    Severity.UNKNOWN: 2,
    Severity.RISK: 3,
}


class TypeNarrowing(enum.Enum):
    """Result of comparing two column types for potential data loss."""

    NARROWING = "narrowing"
    """The new type provably cannot represent some existing values."""

    SAFE = "safe"
    """The type change is a widening / lossless conversion."""

    UNKNOWN = "unknown"
    """There is not enough information to decide."""


@dataclass(frozen=True)
class TypeChangeAssessment:
    """A :class:`.TypeNarrowing` paired with an explanatory
    message."""

    narrowing: TypeNarrowing
    message: str | None = None


class AuditError(util.CommandError):
    """Raised when configured audit severity levels block revision generation.

    The :attr:`.AuditError.report` attribute contains the full
    :class:`.AuditReport` produced by the audit phase; it is also
    machine readable via :meth:`.AuditReport.as_dict` /
    :meth:`.AuditReport.as_json`.

    """

    def __init__(self, message: str, report: "AuditReport") -> None:
        super().__init__(message)
        self.report = report


@dataclass(frozen=True)
class OperationPathEntry:
    """A single node in the :attr:`.AuditFinding.path` chain.

    ``kind`` is a stable machine readable token (e.g.
    ``"upgrade_ops"``, ``"modify_table_ops"``,
    ``"drop_column"``); ``name`` carries the human
    oriented object identifier (table name, token name, ...) where
    applicable.
    """

    kind: str
    name: str | None = None

    def render(self) -> str:
        if self.name:
            return f"{self.kind}[{self.name}]"
        return self.kind


@dataclass
class AuditFinding:
    """A single issue discovered by an audit checker.

    Attributes are plain data so that findings can be serialized to JSON
    without further processing.  The :attr:`.AuditFinding.path`
    attribute is the complete operation path from the root
    :class:`.MigrationScript` down to the offending operation,
    e.g.::

        upgrade_ops[engine1_upgrades] -> modify_table_ops[account] ->
        drop_column[account_id]

    """

    code: str
    severity: Severity
    message: str
    object_name: str | None = None
    operation: str = ""
    dialect_name: str | None = None
    branch: str | None = None
    path: tuple[OperationPathEntry, ...] = ()

    def path_str(self) -> str:
        return " -> ".join(entry.render() for entry in self.path)

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "message": self.message,
            "object_name": self.object_name,
            "operation": self.operation,
            "dialect": self.dialect_name,
            "branch": self.branch,
            "path": [
                {"kind": entry.kind, "name": entry.name} for entry in self.path
            ],
        }


@dataclass
class CheckerError:
    """Record of an unexpected exception raised by an audit checker.

    Checker errors are collected separately from :class:`.AuditFinding`
    instances, so that a buggy custom checker can neither suppress real
    findings nor itself be mistaken for a data-loss risk.
    """

    checker: str
    operation: str
    error: str
    error_type: str
    path: tuple[OperationPathEntry, ...] = ()

    def path_str(self) -> str:
        return " -> ".join(entry.render() for entry in self.path)

    def as_dict(self) -> dict[str, Any]:
        return {
            "checker": self.checker,
            "operation": self.operation,
            "error_type": self.error_type,
            "error": self.error,
            "path": [
                {"kind": entry.kind, "name": entry.name} for entry in self.path
            ],
        }


@dataclass
class AuditContext:
    """Context object passed to every audit checker callable.

    Checkers return either ``None`` or one or many
    :class:`.AuditFinding` instances.  Checkers may also call
    :meth:`.AuditContext.finding` to build a finding with the
    current operation path pre-populated.
    """

    auditor: "OperationAuditor"
    dialect_name: str | None = None
    branch: str | None = None
    direction: str | None = None
    type_check: Any = None
    _path: list[OperationPathEntry] = field(default_factory=list)

    @property
    def path(self) -> tuple[OperationPathEntry, ...]:
        return tuple(self._path)

    def finding(
        self,
        code: str,
        severity: Severity,
        message: str,
        *,
        operation: MigrateOperation,
        object_name: str | None = None,
    ) -> AuditFinding:
        return AuditFinding(
            code=code,
            severity=severity,
            message=message,
            object_name=object_name,
            operation=type(operation).__name__,
            dialect_name=self.dialect_name,
            branch=self.branch,
            path=self.path,
        )


CheckerFn = Callable[[AuditContext, "MigrateOperation"], Any]
"""An audit checker.  May return ``None``, a single
:class:`.AuditFinding`, or a list of
:class:`.AuditFinding` objects."""


@dataclass
class AuditReport:
    """Result of running an :class:`.OperationAuditor` over an
    operation tree."""

    findings: list[AuditFinding] = field(default_factory=list)
    checker_errors: list[CheckerError] = field(default_factory=list)

    def has_severity(self, severities: Sequence[Severity]) -> bool:
        wanted = set(severities)
        return any(finding.severity in wanted for finding in self.findings)

    def findings_at(
        self, severities: Sequence[Severity]
    ) -> list[AuditFinding]:
        wanted = set(severities)
        return [
            finding for finding in self.findings if finding.severity in wanted
        ]

    def as_dict(self) -> dict[str, Any]:
        return {
            "findings": [finding.as_dict() for finding in self.findings],
            "checker_errors": [
                error.as_dict() for error in self.checker_errors
            ],
        }

    def as_json(self, indent: int = 2) -> str:
        return json.dumps(self.as_dict(), indent=indent)

    def render(self) -> str:
        """Return a human readable rendering of the report."""

        lines: list[str] = []
        for finding in self.findings:
            lines.append(
                "[%s] %s: %s"
                % (
                    finding.severity.value.upper(),
                    finding.code,
                    finding.message,
                )
            )
            lines.append(f"    path: {finding.path_str()}")
        for error in self.checker_errors:
            lines.append(
                f"[CHECKER-ERROR] {error.checker} on {error.operation}: "
                f"{error.error_type}: {error.error}"
            )
            lines.append(f"    path: {error.path_str()}")
        return "\n".join(lines)


def _qualified_name(schema: str | None, name: str) -> str:
    return f"{schema}.{name}" if schema else str(name)


_CAMEL_TO_SNAKE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _op_token(op: MigrateOperation) -> str:
    """Machine readable token for a leaf operation, e.g. ``drop_column``."""

    name = type(op).__name__
    if name.endswith("Op"):
        name = name[:-2]
    return _CAMEL_TO_SNAKE.sub("_", name).lower()


# -----------------------------------------------------------------------------
# Operation tree traversal
# -----------------------------------------------------------------------------


def _node_entry(op: MigrateOperation) -> OperationPathEntry:
    if isinstance(op, ops.ModifyTableOps):
        return OperationPathEntry(
            "modify_table_ops",
            _qualified_name(op.schema, op.table_name),
        )
    elif isinstance(op, ops.UpgradeOps):
        return OperationPathEntry(
            "upgrade_ops", getattr(op, "upgrade_token", None)
        )
    elif isinstance(op, ops.DowngradeOps):
        return OperationPathEntry(
            "downgrade_ops", getattr(op, "downgrade_token", None)
        )
    elif isinstance(op, ops.OpContainer):
        return OperationPathEntry("op_container")
    else:
        return OperationPathEntry(_op_token(op))


def walk_operations(
    migration_script: ops.MigrationScript,
) -> Iterator[
    tuple[
        "MigrateOperation",
        tuple[OperationPathEntry, ...],
        str | None,
        str | None,
    ]
]:
    """Yield ``(op, path, branch, direction)`` tuples for every
    operation.

    The traversal covers every entry in
    :attr:`.MigrationScript.upgrade_ops_list` and
    :attr:`.MigrationScript.downgrade_ops_list` (one entry per
    engine in a multi-engine / multidb setup), every level of
    :class:`.OpContainer` / :class:`.ModifyTableOps`
    nesting (i.e. operations hidden inside batch blocks), and every leaf
    operation.

    ``direction`` is ``"upgrade"`` or
    ``"downgrade"``.

    """

    def _walk(
        container: ops.OpContainer,
        path: list[OperationPathEntry],
        branch: str | None,
        direction: str,
    ) -> Iterator[
        tuple[
            "MigrateOperation",
            tuple[OperationPathEntry, ...],
            str | None,
            str | None,
        ]
    ]:
        for child in container.ops:
            entry = _node_entry(child)
            child_path = path + [entry]
            if isinstance(child, ops.OpContainer):
                yield from _walk(child, child_path, branch, direction)
            else:
                yield child, tuple(child_path), branch, direction

    root = [OperationPathEntry("migration_script")]

    for upgrade in migration_script.upgrade_ops_list:
        entry = OperationPathEntry("upgrade_ops", upgrade.upgrade_token)
        yield from _walk(
            upgrade, root + [entry], upgrade.upgrade_token, "upgrade"
        )

    for downgrade in migration_script.downgrade_ops_list:
        entry = OperationPathEntry("downgrade_ops", downgrade.downgrade_token)
        yield from _walk(
            downgrade,
            root + [entry],
            downgrade.downgrade_token,
            "downgrade",
        )


# -----------------------------------------------------------------------------
# Dialect type policies
# -----------------------------------------------------------------------------


def _as_type(type_: Any) -> TypeEngine[Any] | None:
    """Return a concrete :class:`.TypeEngine` instance, or ``None``.

    Both ``alter_column()`` and the op tree may carry types as classes or
    instances; :class:`.NullType` / unrenderable types carry no
    information and therefore result in ``None``.
    """

    if type_ is None:
        return None
    if isinstance(type_, type):
        try:
            type_ = type_()
        except TypeError:
            return None
    if not isinstance(type_, sqltypes.TypeEngine):
        return None
    if type_._type_affinity is sqltypes.NullType:
        return None
    return type_


_INTEGER_ORDER = {
    sqltypes.SmallInteger: 1,
    sqltypes.Integer: 2,
    sqltypes.BigInteger: 3,
}


class DialectTypePolicy:
    """Base class for dialect specific column type change policies.

    A policy inspects an :class:`.AlterColumnOp` and decides whether
    changing ``existing_type`` to ``modify_type`` may lose data.  The
    default implementation :class:`.DefaultDialectTypePolicy` makes
    conservative decisions based on SQLAlchemy type families; dialects may
    register subclasses via :meth:`.DialectTypePolicy.register_policy`
    to account for backend specific behavior (e.g. implicit casts).
    """

    def assess(
        self,
        existing_type: TypeEngine[Any],
        modify_type: TypeEngine[Any],
        alter_op: Any,
    ) -> TypeChangeAssessment:
        raise NotImplementedError()

    _policies: dict[str, type["DialectTypePolicy"]] = {}

    @classmethod
    def register_policy(cls, dialect_name: str):
        """Register a :class:`.DialectTypePolicy` subclass for a dialect
        name."""

        def decorate(policy_cls: type[Any]) -> type[Any]:
            cls._policies[dialect_name] = policy_cls
            return policy_cls

        return decorate

    @classmethod
    def policy_for(cls, dialect_name: str | None) -> "DialectTypePolicy":
        policy_cls = cls._policies.get(
            dialect_name or "", DefaultDialectTypePolicy
        )
        return policy_cls()


def _integer_rank(type_: TypeEngine[Any]) -> int | None:
    for cls, rank in _INTEGER_ORDER.items():
        if isinstance(type_, cls):
            return rank
    return None


class DefaultDialectTypePolicy(DialectTypePolicy):
    """Conservative, dialect-agnostic column type narrowing policy.

    The policy only declares a conversion *safe* or *narrowing* when it can
    reason about both sides; all other conversions are
    :attr:`.TypeNarrowing.UNKNOWN`.
    """

    def assess(
        self,
        existing_type: TypeEngine[Any],
        modify_type: TypeEngine[Any],
        alter_op: Any,
    ) -> TypeChangeAssessment:
        existing_affinity = existing_type._type_affinity
        modify_affinity = modify_type._type_affinity

        if type(existing_type) is type(modify_type):
            return self._assess_same_class(existing_type, modify_type)

        existing_int = _integer_rank(existing_type)
        modify_int = _integer_rank(modify_type)
        if existing_int is not None and modify_int is not None:
            if modify_int < existing_int:
                return TypeChangeAssessment(
                    TypeNarrowing.NARROWING,
                    "integer type reduced from %s to %s; values outside the "
                    "new range cannot be stored"
                    % (
                        type(existing_type).__name__,
                        type(modify_type).__name__,
                    ),
                )
            return TypeChangeAssessment(
                TypeNarrowing.SAFE,
                "integer type widened from %s to %s"
                % (type(existing_type).__name__, type(modify_type).__name__),
            )

        if (
            existing_affinity is modify_affinity
            and existing_affinity is sqltypes.Numeric
        ):
            return self._assess_numeric(existing_type, modify_type)

        if existing_affinity is modify_affinity:
            return self._assess_same_affinity(
                existing_type, modify_type, existing_affinity
            )

        return self._assess_cross_affinity(
            existing_type, modify_type, existing_affinity, modify_affinity
        )

    def _assess_same_class(
        self,
        existing_type: TypeEngine[Any],
        modify_type: TypeEngine[Any],
    ) -> TypeChangeAssessment:
        if isinstance(existing_type, sqltypes.String):
            old_len = getattr(existing_type, "length", None)
            new_len = getattr(modify_type, "length", None)
            if (
                old_len is not None
                and new_len is not None
                and new_len < old_len
            ):
                return TypeChangeAssessment(
                    TypeNarrowing.NARROWING,
                    "string length reduced from %s to %s" % (old_len, new_len),
                )
            if (
                isinstance(existing_type, sqltypes.Enum)
                and isinstance(modify_type, sqltypes.Enum)
                and existing_type.enums
                and modify_type.enums
            ):
                removed = sorted(
                    set(existing_type.enums) - set(modify_type.enums)
                )
                if removed:
                    return TypeChangeAssessment(
                        TypeNarrowing.NARROWING,
                        "enum values removed: %s" % ", ".join(removed),
                    )
            return TypeChangeAssessment(
                TypeNarrowing.SAFE, "same type class; no narrowing detected"
            )
        elif isinstance(existing_type, sqltypes.Numeric):
            return self._assess_numeric(existing_type, modify_type)
        return TypeChangeAssessment(
            TypeNarrowing.SAFE, "same type class; no narrowing detected"
        )

    def _assess_numeric(
        self,
        existing_type: TypeEngine[Any],
        modify_type: TypeEngine[Any],
    ) -> TypeChangeAssessment:
        old_precision = getattr(existing_type, "precision", None)
        new_precision = getattr(modify_type, "precision", None)
        old_scale = getattr(existing_type, "scale", None)
        new_scale = getattr(modify_type, "scale", None)
        if (
            old_precision is not None
            and new_precision is not None
            and new_precision < old_precision
        ):
            return TypeChangeAssessment(
                TypeNarrowing.NARROWING,
                "numeric precision reduced from %s to %s"
                % (old_precision, new_precision),
            )
        if (
            old_scale is not None
            and new_scale is not None
            and new_scale < old_scale
        ):
            return TypeChangeAssessment(
                TypeNarrowing.NARROWING,
                "numeric scale reduced from %s to %s" % (old_scale, new_scale),
            )
        return TypeChangeAssessment(
            TypeNarrowing.SAFE, "numeric change preserves precision and scale"
        )

    def _assess_same_affinity(
        self,
        existing_type: TypeEngine[Any],
        modify_type: TypeEngine[Any],
        affinity: Any,
    ) -> TypeChangeAssessment:
        if affinity is sqltypes.String:
            old_len = getattr(existing_type, "length", None)
            new_len = getattr(modify_type, "length", None)
            if (
                old_len is not None
                and new_len is not None
                and new_len < old_len
            ):
                return TypeChangeAssessment(
                    TypeNarrowing.NARROWING,
                    "string length reduced from %s to %s" % (old_len, new_len),
                )
            return TypeChangeAssessment(
                TypeNarrowing.UNKNOWN,
                "string-family conversion from %s to %s cannot be proven "
                "lossless"
                % (type(existing_type).__name__, type(modify_type).__name__),
            )
        return TypeChangeAssessment(
            TypeNarrowing.UNKNOWN,
            "same type family conversion from %s to %s cannot be classified"
            % (type(existing_type).__name__, type(modify_type).__name__),
        )

    def _assess_cross_affinity(
        self,
        existing_type: TypeEngine[Any],
        modify_type: TypeEngine[Any],
        existing_affinity: Any,
        modify_affinity: Any,
    ) -> TypeChangeAssessment:
        if isinstance(existing_type, sqltypes.Date) and isinstance(
            modify_type, sqltypes.DateTime
        ):
            return TypeChangeAssessment(
                TypeNarrowing.SAFE,
                "Date to DateTime is a widening conversion",
            )

        return TypeChangeAssessment(
            TypeNarrowing.UNKNOWN,
            "type change from %s to %s cannot be proven lossless"
            % (type(existing_type).__name__, type(modify_type).__name__),
        )


# -----------------------------------------------------------------------------
# Auditor and built-in checkers
# -----------------------------------------------------------------------------


#: Default finding codes used by the built-in checkers.
DROP_TABLE_CODE = "drop_table"
DROP_COLUMN_CODE = "drop_column"
ALTER_COLUMN_TYPE_CODE = "alter_column_type"
ALTER_COLUMN_TYPE_UNKNOWN_CODE = "alter_column_type_unknown"


# A type-change callback receives (context, alter_column_op,
# existing_type, modify_type) and returns None (defer to the dialect
# policy), a TypeNarrowing, or a TypeChangeAssessment.
UserTypeCheckFn = Callable[..., Any]


class OperationAuditor:
    """Runs registered audit checkers across a migration operation tree.

    Checkers are registered per :class:`.MigrateOperation` class using
    :meth:`.OperationAuditor.register_checker`, following the same MRO-based
    dispatch mechanism used by the rest of Alembic (renderers, operation
    implementations).  Custom operation classes therefore plug in simply by
    registering a checker for that class.
    """

    _checkers = util.Dispatcher()

    def __init__(self) -> None:
        # per-instance registry that inherits all globally registered
        # checkers but does not mutate them.
        self.dispatch = self._checkers.branch()

    def register_checker(
        self, op_cls: type[MigrateOperation], *, replace: bool = False
    ) -> Callable[[CheckerFn], CheckerFn]:
        """Register a checker callable for the given operation class.

        May be used on the class (globally, as a decorator) or on an
        :class:`.OperationAuditor` instance (locally).
        """

        return self.dispatch.dispatch_for(op_cls, replace=replace)

    @classmethod
    def register_global_checker(
        cls, op_cls: type[MigrateOperation], *, replace: bool = False
    ) -> Callable[[CheckerFn], CheckerFn]:
        return cls._checkers.dispatch_for(op_cls, replace=replace)

    def audit(
        self,
        migration_script: ops.MigrationScript,
        *,
        dialect_names: dict[str, str | None] | None = None,
        type_check: UserTypeCheckFn | None = None,
    ) -> AuditReport:
        """Run all checkers over the given :class:`.MigrationScript`.

        :param migration_script: the operation tree root.
        :param dialect_names: optional mapping of branch token (
         :attr:`.UpgradeOps.upgrade_token`) to dialect name, so that type
         policies can be selected per engine in a multi-engine setup.
        :param type_check: optional user callback consulted ahead of the
         dialect type policy for column type changes.

        Checker exceptions are captured into
        :attr:`.AuditReport.checker_errors` and never abort the traversal.
        """

        report = AuditReport()
        dialect_names = dialect_names or {}

        for operation, path, branch, direction in walk_operations(
            migration_script
        ):
            audit_context = AuditContext(
                auditor=self,
                dialect_name=dialect_names.get(branch),
                branch=branch,
                direction=direction,
                type_check=type_check,
                _path=list(path),
            )

            try:
                checker = self.dispatch.dispatch(operation)
            except ValueError:
                continue

            try:
                result = checker(audit_context, operation)
            except Exception as err:
                report.checker_errors.append(
                    CheckerError(
                        checker=getattr(
                            checker, "__name__", type(checker).__name__
                        ),
                        operation=type(operation).__name__,
                        error=str(err),
                        error_type=type(err).__name__,
                        path=path,
                    )
                )
                continue

            if result is None:
                continue
            findings = (
                result if isinstance(result, (list, tuple)) else [result]
            )
            for finding in findings:
                if isinstance(finding, AuditFinding) and not finding.path:
                    finding.path = path
                    finding.branch = audit_context.branch
                    finding.dialect_name = audit_context.dialect_name
                    finding.operation = (
                        finding.operation or type(operation).__name__
                    )
                report.findings.append(cast(AuditFinding, finding))

        return report


# -----------------------------------------------------------------------------
# Built-in checkers
# -----------------------------------------------------------------------------


def _downgrade_severity(context: AuditContext, default: Severity) -> Severity:
    """Downgrade branches mirror autogenerated upgrades at INFO level."""

    if context.direction == "downgrade":
        return Severity.INFO
    return default


@OperationAuditor.register_global_checker(ops.MigrateOperation)
def _check_operation(
    context: AuditContext, operation: MigrateOperation
) -> None:
    # base no-op checker so dispatch always resolves.
    return None


@OperationAuditor.register_global_checker(ops.DropTableOp)
def _check_drop_table(
    context: AuditContext, operation: ops.DropTableOp
) -> AuditFinding:
    table_name = _qualified_name(operation.schema, operation.table_name)
    return context.finding(
        DROP_TABLE_CODE,
        _downgrade_severity(context, Severity.RISK),
        "dropping table %s removes all data it contains" % table_name,
        operation=operation,
        object_name=table_name,
    )


@OperationAuditor.register_global_checker(ops.DropColumnOp)
def _check_drop_column(
    context: AuditContext, operation: ops.DropColumnOp
) -> AuditFinding:
    table_name = _qualified_name(operation.schema, operation.table_name)
    full_name = "%s.%s" % (table_name, operation.column_name)
    return context.finding(
        DROP_COLUMN_CODE,
        _downgrade_severity(context, Severity.RISK),
        "dropping column %s discards all values stored in it" % full_name,
        operation=operation,
        object_name=full_name,
    )


def _assess_alter_column_type(
    context: AuditContext,
    operation: Any,
) -> AuditFinding | None:
    if operation.modify_type is None:
        return None

    existing_type = _as_type(operation.existing_type)
    modify_type = _as_type(operation.modify_type)
    type_check = context.type_check

    if existing_type is None or modify_type is None:
        return context.finding(
            ALTER_COLUMN_TYPE_UNKNOWN_CODE,
            Severity.UNKNOWN,
            "column %s.%s type cannot be classified: %s type information "
            "missing; cannot prove the change is lossless"
            % (
                operation.table_name,
                operation.column_name,
                "existing" if existing_type is None else "new",
            ),
            operation=operation,
            object_name="%s.%s"
            % (operation.table_name, operation.column_name),
        )

    assessment: TypeChangeAssessment | None = None

    if type_check is not None:
        user_result = type_check(
            context, operation, existing_type, modify_type
        )
        if user_result is not None:
            if isinstance(user_result, TypeChangeAssessment):
                assessment = user_result
            elif isinstance(user_result, TypeNarrowing):
                assessment = TypeChangeAssessment(user_result)
            else:
                raise ValueError(
                    "revision_audit_type_check callback must return None, "
                    "a TypeNarrowing, or a TypeChangeAssessment; got %r"
                    % (user_result,)
                )

    if assessment is None:
        policy = DialectTypePolicy.policy_for(context.dialect_name)
        assessment = policy.assess(existing_type, modify_type, operation)

    table_name = _qualified_name(operation.schema, operation.table_name)
    full_name = "%s.%s" % (table_name, operation.column_name)

    if assessment.narrowing is TypeNarrowing.NARROWING:
        return context.finding(
            ALTER_COLUMN_TYPE_CODE,
            _downgrade_severity(context, Severity.WARNING),
            "column %s type change from %s to %s may lose data%s"
            % (
                full_name,
                type(existing_type).__name__,
                type(modify_type).__name__,
                (": %s" % assessment.message) if assessment.message else "",
            ),
            operation=operation,
            object_name=full_name,
        )
    elif assessment.narrowing is TypeNarrowing.UNKNOWN:
        return context.finding(
            ALTER_COLUMN_TYPE_UNKNOWN_CODE,
            Severity.UNKNOWN,
            "column %s type change from %s to %s cannot be proven lossless"
            "%s"
            % (
                full_name,
                type(existing_type).__name__,
                type(modify_type).__name__,
                (": %s" % assessment.message) if assessment.message else "",
            ),
            operation=operation,
            object_name=full_name,
        )
    return None


@OperationAuditor.register_global_checker(ops.AlterColumnOp)
def _check_alter_column(
    context: AuditContext, operation: ops.AlterColumnOp
) -> AuditFinding | None:
    return _assess_alter_column_type(context, operation)


def audit_migration_script(
    migration_script: ops.MigrationScript,
    *,
    dialect_names: dict[str, str | None] | None = None,
    type_check: UserTypeCheckFn | None = None,
    auditor: OperationAuditor | None = None,
) -> AuditReport:
    """Convenience function: audit a single :class:`.MigrationScript`."""

    auditor = auditor or OperationAuditor()
    return auditor.audit(
        migration_script,
        dialect_names=dialect_names,
        type_check=type_check,
    )
