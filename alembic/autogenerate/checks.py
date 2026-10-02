from __future__ import annotations

from collections.abc import Callable
from collections.abc import Iterable
from collections.abc import Sequence
from dataclasses import dataclass
from dataclasses import field
import enum
import re
from typing import Any
from typing import TYPE_CHECKING

from sqlalchemy import types as sqltypes

from ..operations import ops

if TYPE_CHECKING:
    from ..runtime.migration import MigrationContext

    OperationCheckerResult = (
        RiskFinding
        | RiskLevel
        | str
        | None
        | Iterable[RiskFinding | RiskLevel | str]
    )
    OperationChecker = Callable[
        [
            MigrationContext | None,
            ops.MigrateOperation,
            OperationCheckContext,
        ],
        OperationCheckerResult,
    ]
    TypeNarrowingFn = Callable[
        [MigrationContext | None, Any, Any], TypeRisk | bool | None
    ]


class RiskLevel(enum.Enum):
    """Severity levels reported by migration operation checkers."""

    INFO = "info"
    UNKNOWN = "unknown"
    WARNING = "warning"
    DANGER = "danger"


class TypeRisk(enum.Enum):
    """Result returned by a type-narrowing strategy."""

    SAFE = "safe"
    RISK = "risk"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class OperationCheckContext:
    """Location information passed to an operation checker."""

    migration_context: MigrationContext | None
    direction: str
    branch: str
    path: tuple[str, ...]


@dataclass(frozen=True)
class RiskFinding:
    """A risk found while checking a migration operation tree."""

    level: RiskLevel
    operation: str
    object_type: str
    object_name: str
    path: tuple[str, ...]
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    direction: str = "upgrades"
    branch: str = "upgrades"
    schema: str | None = None
    checker: str = "alembic"

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level.value,
            "operation": self.operation,
            "object_type": self.object_type,
            "object_name": self.object_name,
            "path": list(self.path),
            "message": self.message,
            "details": self.details,
            "direction": self.direction,
            "branch": self.branch,
            "schema": self.schema,
            "checker": self.checker,
        }


@dataclass(frozen=True)
class CheckerError:
    """An error raised by a checker, kept separate from risk findings."""

    checker: str
    operation: str
    path: tuple[str, ...]
    error_type: str
    message: str
    direction: str = "upgrades"
    branch: str = "upgrades"

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": "error",
            "checker": self.checker,
            "operation": self.operation,
            "path": list(self.path),
            "error_type": self.error_type,
            "message": self.message,
            "direction": self.direction,
            "branch": self.branch,
        }


@dataclass
class RiskReport:
    """Machine-readable result of checking one or more operation trees."""

    findings: list[RiskFinding] = field(default_factory=list)
    errors: list[CheckerError] = field(default_factory=list)

    def findings_for(self, *levels: RiskLevel | str) -> list[RiskFinding]:
        wanted = {_level_value(level) for level in levels}
        return [
            finding
            for finding in self.findings
            if finding.level.value in wanted
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [item.to_dict() for item in self.findings],
            "errors": [item.to_dict() for item in self.errors],
        }


_operation_checkers: list[
    tuple[type[ops.MigrateOperation], str | None, Callable[..., Any]]
] = []
_type_narrowing_strategies: dict[str, Callable[..., Any]] = {}


def register_operation_checker(
    operation_cls: type[ops.MigrateOperation],
    *,
    dialect: str | None = None,
) -> Callable[[OperationChecker], OperationChecker]:
    """Register a checker for a built-in or custom operation class."""

    def decorate(fn: OperationChecker) -> OperationChecker:
        entry = (operation_cls, dialect, fn)
        if entry not in _operation_checkers:
            _operation_checkers.append(entry)
        return fn

    return decorate


def register_type_narrowing_strategy(
    dialect: str,
    *,
    replace: bool = False,
) -> Callable[[TypeNarrowingFn], TypeNarrowingFn]:
    """Register a dialect-specific type-narrowing strategy."""

    def decorate(fn: TypeNarrowingFn) -> TypeNarrowingFn:
        if dialect in _type_narrowing_strategies and not replace:
            raise ValueError(
                f"Type narrowing strategy for dialect {dialect!r} "
                "is already registered"
            )
        _type_narrowing_strategies[dialect] = fn
        return fn

    return decorate


def _level_value(level: RiskLevel | str) -> str:
    if isinstance(level, RiskLevel):
        return level.value
    value = str(level).lower()
    if value == "error":
        return value
    return RiskLevel(value).value


def _operation_name(operation: ops.MigrateOperation) -> str:
    name = type(operation).__name__
    if isinstance(operation, (ops.UpgradeOps, ops.DowngradeOps)):
        return (
            "upgrades"
            if isinstance(operation, ops.UpgradeOps)
            else ("downgrades")
        )
    if name.endswith("Ops"):
        name = name[:-3]
    elif name.endswith("Op"):
        name = name[:-2]
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _qualified_name(schema: str | None, name: str | None) -> str:
    return f"{schema}.{name}" if schema else str(name)


def _finding(
    *,
    level: RiskLevel,
    operation: ops.MigrateOperation,
    object_type: str,
    object_name: str,
    path: tuple[str, ...],
    message: str,
    check_context: OperationCheckContext,
    details: dict[str, Any] | None = None,
    schema: str | None = None,
    checker: str = "alembic",
) -> RiskFinding:
    return RiskFinding(
        level=level,
        operation=_operation_name(operation),
        object_type=object_type,
        object_name=object_name,
        path=path,
        message=message,
        details=details or {},
        direction=check_context.direction,
        branch=check_context.branch,
        schema=schema,
        checker=checker,
    )


def _as_type(type_: Any) -> Any:
    if isinstance(type_, type) and issubclass(type_, sqltypes.TypeEngine):
        try:
            return type_()
        except Exception:
            return sqltypes.NULLTYPE
    return type_


def _numeric_bounds(type_: Any) -> tuple[Any, Any]:
    return getattr(type_, "precision", None), getattr(type_, "scale", 0)


def _integer_rank(type_: Any) -> int | None:
    if isinstance(type_, sqltypes.SmallInteger):
        return 1
    if type(type_) is sqltypes.Integer:
        return 2
    if isinstance(type_, sqltypes.BigInteger):
        return 3
    return None


def _default_type_narrowing(
    context: MigrationContext | None,
    existing_type: Any,
    new_type: Any,
) -> TypeRisk:
    old = _as_type(existing_type)
    new = _as_type(new_type)

    if old is None or new is None:
        return TypeRisk.UNKNOWN
    if old._type_affinity is None:
        return TypeRisk.UNKNOWN
    if new._type_affinity is None:
        return TypeRisk.UNKNOWN
    if old._type_affinity is sqltypes.NullType:
        return TypeRisk.UNKNOWN
    if new._type_affinity is sqltypes.NullType:
        return TypeRisk.UNKNOWN
    if type(old) is type(new):
        old_attrs = old.__dict__
        new_attrs = new.__dict__
        if old_attrs == new_attrs:
            return TypeRisk.SAFE

    old_affinity = old._type_affinity
    new_affinity = new._type_affinity

    if old_affinity is sqltypes.String and new_affinity is sqltypes.String:
        if isinstance(old, sqltypes.Text):
            return (
                TypeRisk.SAFE
                if isinstance(new, sqltypes.Text)
                else TypeRisk.RISK
            )
        if isinstance(new, sqltypes.Text):
            return TypeRisk.SAFE
        if (
            isinstance(old, sqltypes.String)
            and isinstance(new, sqltypes.String)
            and not isinstance(new, sqltypes.Text)
        ):
            if old.length is None:
                return TypeRisk.SAFE
            if new.length is None or new.length >= old.length:
                return TypeRisk.SAFE
            return TypeRisk.RISK
        if isinstance(old, sqltypes.Enum) and isinstance(new, sqltypes.Enum):
            old_values = set(old.enums)
            new_values = set(new.enums)
            if new_values.issuperset(old_values):
                return TypeRisk.SAFE
            if new_values.issubset(old_values):
                return TypeRisk.RISK
        return TypeRisk.UNKNOWN

    old_integer_rank = _integer_rank(old)
    new_integer_rank = _integer_rank(new)
    if old_integer_rank is not None and new_integer_rank is not None:
        return (
            TypeRisk.SAFE
            if new_integer_rank >= old_integer_rank
            else TypeRisk.RISK
        )

    if old_affinity is sqltypes.Numeric and new_affinity is sqltypes.Numeric:
        if isinstance(old, sqltypes.Float) or isinstance(new, sqltypes.Float):
            return TypeRisk.UNKNOWN
        old_precision, old_scale = _numeric_bounds(old)
        new_precision, new_scale = _numeric_bounds(new)
        if old_precision is None or new_precision is None:
            return TypeRisk.UNKNOWN
        if new_scale > old_scale:
            return TypeRisk.UNKNOWN
        old_integer_digits = old_precision - old_scale
        new_integer_digits = new_precision - new_scale
        if new_integer_digits < old_integer_digits:
            return TypeRisk.RISK
        if new_scale < old_scale:
            return TypeRisk.UNKNOWN
        return TypeRisk.SAFE

    if old_affinity is new_affinity:
        return TypeRisk.UNKNOWN
    return TypeRisk.UNKNOWN


def _type_risk(
    context: MigrationContext | None,
    existing_type: Any,
    new_type: Any,
) -> TypeRisk:
    user_callback = None
    if context is not None:
        user_callback = context.opts.get("migration_risk_type_fn")
    if user_callback is not None:
        result = user_callback(context, existing_type, new_type)
        if isinstance(result, TypeRisk):
            return result
        if result is True:
            return TypeRisk.RISK
        if result is False:
            return TypeRisk.SAFE
        if result is None:
            return TypeRisk.UNKNOWN
        return TypeRisk.UNKNOWN

    dialect_name = context.dialect.name if context is not None else None
    if dialect_name and dialect_name in _type_narrowing_strategies:
        result = _type_narrowing_strategies[dialect_name](
            context, existing_type, new_type
        )
        if isinstance(result, TypeRisk):
            return result
        if result is True:
            return TypeRisk.RISK
        if result is False:
            return TypeRisk.SAFE
        if result is None:
            return TypeRisk.UNKNOWN
        return TypeRisk.UNKNOWN
    return _default_type_narrowing(context, existing_type, new_type)


@register_operation_checker(ops.DropTableOp)
def _check_drop_table(
    context: MigrationContext | None,
    operation: ops.DropTableOp,
    check_context: OperationCheckContext,
) -> RiskFinding:
    table_name = _qualified_name(operation.schema, operation.table_name)
    return _finding(
        level=RiskLevel.DANGER,
        operation=operation,
        object_type="table",
        object_name=table_name,
        path=(*check_context.path, "drop_table"),
        message=f"Dropping table {table_name!r} removes all table data",
        check_context=check_context,
        details={"if_exists": operation.if_exists},
        schema=operation.schema,
    )


@register_operation_checker(ops.DropColumnOp)
def _check_drop_column(
    context: MigrationContext | None,
    operation: ops.DropColumnOp,
    check_context: OperationCheckContext,
) -> RiskFinding:
    table_name = _qualified_name(operation.schema, operation.table_name)
    column_name = operation.column_name
    return _finding(
        level=RiskLevel.DANGER,
        operation=operation,
        object_type="column",
        object_name=f"{table_name}.{column_name}",
        path=(*check_context.path, "drop_column"),
        message=(
            f"Dropping column {column_name!r} from table "
            f"{table_name!r} removes column data"
        ),
        check_context=check_context,
        details={"if_exists": operation.if_exists},
        schema=operation.schema,
    )


@register_operation_checker(ops.AlterColumnOp)
def _check_alter_column(
    context: MigrationContext | None,
    operation: ops.AlterColumnOp,
    check_context: OperationCheckContext,
) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    table_name = _qualified_name(operation.schema, operation.table_name)
    column_name = operation.column_name
    object_name = f"{table_name}.{column_name}"

    if operation.modify_type is not None:
        type_result = _type_risk(
            context, operation.existing_type, operation.modify_type
        )
        if type_result is not TypeRisk.SAFE:
            findings.append(
                _finding(
                    level=(
                        RiskLevel.DANGER
                        if type_result is TypeRisk.RISK
                        else RiskLevel.UNKNOWN
                    ),
                    operation=operation,
                    object_type="column_type",
                    object_name=object_name,
                    path=(*check_context.path, "alter_column", "type"),
                    message=(
                        "Column type change may narrow data"
                        if type_result is TypeRisk.RISK
                        else "Unable to determine whether column type "
                        "change may narrow data"
                    ),
                    check_context=check_context,
                    details={
                        "existing_type": repr(operation.existing_type),
                        "new_type": repr(operation.modify_type),
                        "type_risk": type_result.value,
                    },
                    schema=operation.schema,
                )
            )

    if operation.modify_nullable is False and (
        operation.existing_nullable is None
        or operation.existing_nullable is True
    ):
        findings.append(
            _finding(
                level=(
                    RiskLevel.WARNING
                    if operation.existing_nullable is True
                    else RiskLevel.UNKNOWN
                ),
                operation=operation,
                object_type="column_nullability",
                object_name=object_name,
                path=(
                    *check_context.path,
                    "alter_column",
                    "nullable",
                ),
                message="Making a column NOT NULL may fail on existing NULLs",
                check_context=check_context,
                details={
                    "existing_nullable": operation.existing_nullable,
                    "new_nullable": operation.modify_nullable,
                },
                schema=operation.schema,
            )
        )

    return findings


def _checkers_for(
    operation: ops.MigrateOperation,
    migration_context: MigrationContext | None,
) -> list[tuple[OperationChecker, str]]:
    dialect_name = (
        migration_context.dialect.name
        if migration_context is not None
        else None
    )
    result: list[tuple[OperationChecker, str]] = []
    seen: set[object] = set()
    for operation_cls in type(operation).__mro__:
        dialect_entries: list[tuple[OperationChecker, str]] = []
        default_entries: list[tuple[OperationChecker, str]] = []
        for registered_cls, registered_dialect, checker in _operation_checkers:
            if registered_cls is not operation_cls or checker in seen:
                continue
            name = getattr(checker, "__qualname__", "custom")
            module = getattr(checker, "__module__", "")
            checker_name = f"{module}.{name}" if module else name
            if registered_dialect is not None:
                if registered_dialect == dialect_name:
                    dialect_entries.append((checker, checker_name))
            else:
                default_entries.append((checker, checker_name))
        result.extend(dialect_entries)
        result.extend(default_entries)
        seen.update(checker for checker, _ in dialect_entries)
        seen.update(checker for checker, _ in default_entries)
    return result


def _default_object(
    operation: ops.MigrateOperation,
) -> tuple[str, str, str | None]:
    if isinstance(operation, ops.AlterTableOp):
        table_name = _qualified_name(operation.schema, operation.table_name)
        column_name = getattr(operation, "column_name", None)
        if column_name:
            return (
                "column",
                f"{table_name}.{column_name}",
                operation.schema,
            )
        return "table", table_name, operation.schema
    return "operation", _operation_name(operation), None


def _coerce_result(
    result: OperationCheckerResult,
    operation: ops.MigrateOperation,
    check_context: OperationCheckContext,
) -> list[RiskFinding]:
    if result is None:
        return []
    if isinstance(result, RiskFinding):
        return [result]

    if isinstance(result, (RiskLevel, str)):
        level = result if isinstance(result, RiskLevel) else RiskLevel(result)
        raw_results: Iterable[RiskLevel | str] = [level]
    else:
        raw_results = result

    findings = []
    object_type, object_name, schema = _default_object(operation)
    for raw_result in raw_results:
        if isinstance(raw_result, RiskFinding):
            findings.append(raw_result)
            continue
        level = (
            raw_result
            if isinstance(raw_result, RiskLevel)
            else RiskLevel(raw_result)
        )
        findings.append(
            _finding(
                level=level,
                operation=operation,
                object_type=object_type,
                object_name=object_name,
                path=(*check_context.path, _operation_name(operation)),
                message=f"Migration operation reported {level.value} risk",
                check_context=check_context,
                schema=schema,
                checker="custom",
            )
        )
    return findings


def _container_path(
    operation: ops.OpContainer,
    context: OperationCheckContext,
    render_as_batch: bool,
) -> tuple[str, ...]:
    if isinstance(operation, (ops.UpgradeOps, ops.DowngradeOps)):
        return (context.direction,)
    if isinstance(operation, ops.ModifyTableOps):
        table_name = _qualified_name(operation.schema, operation.table_name)
        directive = "batch_alter_table" if render_as_batch else "alter_table"
        return (*context.path, directive, table_name)
    return (*context.path, _operation_name(operation))


def _check_tree(
    operation: ops.MigrateOperation,
    migration_context: MigrationContext | None,
    parent_context: OperationCheckContext,
    report: RiskReport,
) -> None:
    render_as_batch = bool(
        migration_context is not None
        and migration_context.opts.get("render_as_batch", False)
    )

    is_container = hasattr(operation, "ops") and isinstance(
        getattr(operation, "ops"), Iterable
    )

    for checker, checker_name in _checkers_for(operation, migration_context):
        try:
            result = checker(migration_context, operation, parent_context)
        except Exception as error:
            report.errors.append(
                CheckerError(
                    checker=checker_name,
                    operation=_operation_name(operation),
                    path=parent_context.path,
                    error_type=type(error).__name__,
                    message=str(error),
                    direction=parent_context.direction,
                    branch=parent_context.branch,
                )
            )
        else:
            report.findings.extend(
                _coerce_result(result, operation, parent_context)
            )

    if is_container:
        child_path = (
            _container_path(operation, parent_context, render_as_batch)
            if isinstance(operation, ops.ModifyTableOps)
            else (*parent_context.path, _operation_name(operation))
        )
        for index, child in enumerate(operation.ops):
            child_context = OperationCheckContext(
                migration_context=migration_context,
                direction=parent_context.direction,
                branch=parent_context.branch,
                path=(*child_path, str(index)),
            )
            _check_tree(child, migration_context, child_context, report)
        return


def check_operations(
    operations: ops.OpContainer,
    *,
    migration_context: MigrationContext | None = None,
    direction: str = "upgrades",
    branch: str | None = None,
) -> RiskReport:
    """Check one upgrade or downgrade operation tree."""

    report = RiskReport()
    check_context = OperationCheckContext(
        migration_context=migration_context,
        direction=direction,
        branch=branch or direction,
        path=(),
    )
    _check_tree(operations, migration_context, check_context, report)
    return report


def check_migration_script(
    migration_script: ops.MigrationScript,
    *,
    migration_context: MigrationContext | None = None,
    migration_contexts: Sequence[MigrationContext] | None = None,
) -> RiskReport:
    """Check upgrade, downgrade and multi-engine branches in a script."""

    report = RiskReport()
    contexts = (
        list(migration_contexts)
        if migration_contexts is not None
        else ([migration_context] if migration_context is not None else [])
    )

    for index, upgrade_ops in enumerate(migration_script.upgrade_ops_list):
        branch_context = (
            contexts[index]
            if index < len(contexts)
            else (contexts[-1] if contexts else None)
        )
        branch_name = upgrade_ops.upgrade_token
        branch_report = check_operations(
            upgrade_ops,
            migration_context=branch_context,
            direction="upgrades",
            branch=branch_name,
        )
        report.findings.extend(branch_report.findings)
        report.errors.extend(branch_report.errors)

    for index, downgrade_ops in enumerate(migration_script.downgrade_ops_list):
        branch_context = (
            contexts[index]
            if index < len(contexts)
            else (contexts[-1] if contexts else None)
        )
        branch_name = downgrade_ops.downgrade_token
        branch_report = check_operations(
            downgrade_ops,
            migration_context=branch_context,
            direction="downgrades",
            branch=branch_name,
        )
        report.findings.extend(branch_report.findings)
        report.errors.extend(branch_report.errors)

    return report
