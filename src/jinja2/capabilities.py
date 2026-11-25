"""Capability review helpers for sandboxed Jinja templates."""

from __future__ import annotations

import contextvars
import hashlib
import types
import typing as t
from dataclasses import dataclass
from dataclasses import field
from dataclasses import replace
from functools import wraps
from io import BytesIO

from .bccache import BytecodeCache
from . import meta
from . import nodes
from .exceptions import SecurityError
from .utils import _PassArg

if t.TYPE_CHECKING:
    from .environment import Environment


ACTIVE_GRANT: contextvars.ContextVar[CapabilityGrant | None] = (
    contextvars.ContextVar("jinja2_capability_grant", default=None)
)


class CapabilityError(SecurityError):
    """Base class for capability review failures."""

    review: CapabilityReview | None

    def __init__(self, message: str | None = None, review: CapabilityReview | None = None) -> None:
        self.review = review
        if message is None:
            message = "Template capabilities require review before execution."
        super().__init__(message)


class CapabilityReviewRequired(CapabilityError):
    """Raised when a template does not have a current approval."""


class UnapprovedCapabilityError(CapabilityReviewRequired):
    """Alias for callers using the unapproved naming."""


class StaleCapabilityError(CapabilityReviewRequired):
    """Raised when a bound callable changed after review."""


class UnknownDynamicCallError(CapabilityReviewRequired):
    """Raised when an unresolvable dynamic call is executed."""


def _sha256() -> hashlib._Hash:
    return hashlib.sha256()


def _update_fingerprint(h: hashlib._Hash, value: t.Any) -> None:
    h.update(type(value).__module__.encode("utf-8", "replace"))
    h.update(b"\0")
    h.update(type(value).__qualname__.encode("utf-8", "replace"))
    h.update(b"\0")
    h.update(repr(value).encode("utf-8", "replace"))
    h.update(b"\0")


def implementation_fingerprint(obj: t.Any) -> str:
    """Return a best-effort hash of a callable implementation."""
    h = _sha256()
    h.update(getattr(obj, "__module__", type(obj).__module__).encode("utf-8", "replace"))
    h.update(b":")
    qualname = getattr(obj, "__qualname__", getattr(obj, "__name__", type(obj).__qualname__))
    h.update(str(qualname).encode("utf-8", "replace"))

    code = getattr(obj, "__code__", None)
    if code is not None:
        h.update(b"\0code\0")
        h.update(code.co_code)
        for const in code.co_consts:
            if isinstance(const, (str, int, float, bool, bytes, type(None))):
                _update_fingerprint(h, const)

    closure = getattr(obj, "__closure__", None)
    if closure:
        h.update(b"\0closure\0")
        for cell in closure:
            try:
                value = cell.cell_contents
            except ValueError:
                h.update(b"<empty>")
            else:
                h.update(str(id(value)).encode("ascii"))
                h.update(type(value).__qualname__.encode("utf-8", "replace"))

    if isinstance(obj, types.MethodType):
        h.update(b"\0method\0")
        h.update(getattr(obj.__func__, "__qualname__", "").encode("utf-8", "replace"))
        h.update(str(id(obj.__self__)).encode("ascii"))

    if isinstance(obj, type):
        mro = ".".join(cls.__qualname__ for cls in obj.__mro__)
        h.update(b"\0type\0")
        h.update(mro.encode("utf-8", "replace"))

    return h.hexdigest()


def callable_fingerprint(obj: t.Any) -> str:
    """Fingerprint an effective callable, including object identity."""
    h = _sha256()
    h.update(implementation_fingerprint(obj).encode("ascii"))
    h.update(b"\0identity\0")
    h.update(str(id(obj)).encode("ascii"))
    return h.hexdigest()


def pass_arg_name(obj: t.Any) -> str | None:
    pass_arg = _PassArg.from_obj(obj)
    return None if pass_arg is None else pass_arg.name


@dataclass(frozen=True)
class CallableBinding:
    name: str
    kind: str
    fingerprint: str
    implementation_fingerprint: str
    pass_arg: str | None
    safe: bool
    origin: str
    obj: t.Any = field(default=None, compare=False, repr=False)

    def matches(self, obj: t.Any) -> bool:
        return obj is self.obj or callable_fingerprint(obj) == self.fingerprint


CapabilityBinding = CallableBinding


@dataclass(frozen=True)
class TemplateReferenceCapability:
    kind: str
    name: str | None = None
    names: tuple[str, ...] = ()
    dynamic: bool = False
    lineno: int | None = None

    @property
    def deferred(self) -> bool:
        return self.dynamic

    @property
    def lazy(self) -> bool:
        return self.dynamic


DeferredTemplateReference = TemplateReferenceCapability
LazyTemplateReference = TemplateReferenceCapability


@dataclass(frozen=True)
class DynamicCallCapability:
    description: str
    kind: str = "dynamic"
    name: str | None = None
    lineno: int | None = None
    known: bool = False
    reason: str = ""
    binding: CallableBinding | None = None


UnknownDynamicCall = DynamicCallCapability


@dataclass(frozen=True)
class CompiledDependencies:
    filters: frozenset[str] = frozenset()
    tests: frozenset[str] = frozenset()
    globals: frozenset[str] = frozenset()
    undeclared_variables: frozenset[str] = frozenset()
    template_references: tuple[TemplateReferenceCapability, ...] = ()
    dynamic_calls: tuple[DynamicCallCapability, ...] = ()

    @property
    def filter_names(self) -> frozenset[str]:
        return self.filters

    @property
    def test_names(self) -> frozenset[str]:
        return self.tests

    @property
    def global_names(self) -> frozenset[str]:
        return self.globals

    @property
    def referenced_templates(self) -> tuple[str | None, ...]:
        result: list[str | None] = []
        for ref in self.template_references:
            if ref.dynamic:
                result.append(None)
            else:
                result.extend(ref.names or ((ref.name,) if ref.name else ()))
        return tuple(result)

    @property
    def lazy_references(self) -> tuple[TemplateReferenceCapability, ...]:
        return tuple(ref for ref in self.template_references if ref.dynamic)

    @property
    def deferred_references(self) -> tuple[TemplateReferenceCapability, ...]:
        return self.lazy_references

    @property
    def unknown_dynamic_calls(self) -> tuple[DynamicCallCapability, ...]:
        return tuple(call for call in self.dynamic_calls if not call.known)


TemplateDependencies = CompiledDependencies


@dataclass(frozen=True)
class OverlayInfo:
    class_name: str
    chain: tuple[str, ...]
    sandboxed: bool
    is_async: bool
    optimized: bool
    fingerprint: str


@dataclass(frozen=True)
class CapabilityReport:
    key: str
    name: str | None
    source_checksum: str
    overlay: OverlayInfo
    dependencies: CompiledDependencies
    fingerprint: str
    filename: str | None = None
    cache_key: str | None = None
    filter_bindings: dict[str, CallableBinding] = field(default_factory=dict)
    test_bindings: dict[str, CallableBinding] = field(default_factory=dict)
    global_bindings: dict[str, CallableBinding] = field(default_factory=dict)
    context_bindings: dict[str, CallableBinding] = field(default_factory=dict)
    status: str = "review_required"
    approved: bool = False
    approved_fingerprint: str | None = None
    changed_filters: tuple[str, ...] = ()
    changed_tests: tuple[str, ...] = ()
    changed_globals: tuple[str, ...] = ()
    added_dependencies: tuple[str, ...] = ()
    removed_dependencies: tuple[str, ...] = ()
    block_reasons: tuple[str, ...] = ()
    reviewer: t.Any = field(default=None, compare=False, repr=False)

    @property
    def filters(self) -> dict[str, t.Any]:
        return {name: binding.obj for name, binding in self.filter_bindings.items()}

    @property
    def tests(self) -> dict[str, t.Any]:
        return {name: binding.obj for name, binding in self.test_bindings.items()}

    @property
    def globals(self) -> dict[str, t.Any]:
        return {name: binding.obj for name, binding in self.global_bindings.items()}

    @property
    def bindings(self) -> tuple[CallableBinding, ...]:
        return (
            tuple(self.filter_bindings.values())
            + tuple(self.test_bindings.values())
            + tuple(self.global_bindings.values())
            + tuple(self.context_bindings.values())
        )

    @property
    def template_references(self) -> tuple[TemplateReferenceCapability, ...]:
        return self.dependencies.template_references

    @property
    def lazy_references(self) -> tuple[TemplateReferenceCapability, ...]:
        return self.dependencies.lazy_references

    @property
    def deferred_references(self) -> tuple[TemplateReferenceCapability, ...]:
        return self.dependencies.deferred_references

    @property
    def dynamic_calls(self) -> tuple[DynamicCallCapability, ...]:
        return self.dependencies.dynamic_calls

    @property
    def unknown_dynamic_calls(self) -> tuple[DynamicCallCapability, ...]:
        return self.dependencies.unknown_dynamic_calls

    @property
    def blocked(self) -> bool:
        return bool(self.block_reasons)

    @property
    def requires_review(self) -> bool:
        return not self.approved or self.status != "approved"

    needs_review = requires_review

    @property
    def compiled_dependencies(self) -> CompiledDependencies:
        return self.dependencies

    @property
    def deps(self) -> CompiledDependencies:
        return self.dependencies

    @property
    def capability_fingerprint(self) -> str:
        return self.fingerprint

    @property
    def digest(self) -> str:
        return self.fingerprint

    @property
    def unknown_calls(self) -> tuple[DynamicCallCapability, ...]:
        return self.unknown_dynamic_calls

    @property
    def runtime_bindings(self) -> tuple[CallableBinding, ...]:
        return self.bindings

    def recheck(self, **kwargs: t.Any) -> CapabilityReport:
        if self.reviewer is None:
            raise CapabilityError("Report is not attached to a reviewer.", self)
        target = self.name if self.name is not None else self.key
        return self.reviewer.review(target, **kwargs)

    def approve(self, **kwargs: t.Any) -> CapabilityReport:
        if self.reviewer is None:
            raise CapabilityError("Report is not attached to a reviewer.", self)
        return self.reviewer.approve(report=self, **kwargs)

    def invalidate(self) -> None:
        if self.reviewer is not None:
            self.reviewer.registry.remove(self.key)

    @property
    def changed_capabilities(self) -> tuple[str, ...]:
        return (
            tuple(f"filter:{name}" for name in self.changed_filters)
            + tuple(f"test:{name}" for name in self.changed_tests)
            + tuple(f"global:{name}" for name in self.changed_globals)
        )

    def diff_against(self, old: CapabilityReport | None) -> CapabilityDiff:
        return diff_reports(old, self)


CapabilityReview = CapabilityReport
CapabilityAssessment = CapabilityReport
CapabilityManifest = CapabilityReport
CapabilitySnapshot = CapabilityReport


@dataclass(frozen=True)
class CapabilityDiff:
    old_key: str | None
    new_key: str
    changed_filters: tuple[str, ...] = ()
    changed_tests: tuple[str, ...] = ()
    changed_globals: tuple[str, ...] = ()
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    source_changed: bool = False
    overlay_changed: bool = False

    @property
    def affected(self) -> bool:
        return bool(
            self.changed_filters
            or self.changed_tests
            or self.changed_globals
            or self.added
            or self.removed
            or self.source_changed
            or self.overlay_changed
        )


ReviewChange = CapabilityDiff


@dataclass(frozen=True)
class Approval:
    key: str
    fingerprint: str
    report: CapabilityReport
    note: str | None = None
    allowed_unknown: bool = False
    allowed_unsafe: bool = False


class CapabilityRegistry:
    """Approved capability fingerprints keyed by template key."""

    def __init__(self) -> None:
        self._approvals: dict[str, Approval] = {}
        self.last_reports: dict[str, CapabilityReport] = {}

    def remember(self, report: CapabilityReport) -> None:
        self.last_reports[report.key] = report

    def last_report(self, key: str) -> CapabilityReport | None:
        return self.last_reports.get(key)

    def approve(
        self,
        report: CapabilityReport,
        note: str | None = None,
        *,
        allowed_unknown: bool = False,
        allowed_unsafe: bool = False,
    ) -> Approval:
        approved = replace(
            report,
            status="approved",
            approved=True,
            approved_fingerprint=report.fingerprint,
            block_reasons=(),
        )
        record = Approval(
            report.key,
            report.fingerprint,
            approved,
            note,
            allowed_unknown=allowed_unknown,
            allowed_unsafe=allowed_unsafe,
        )
        self._approvals[report.key] = record
        return record

    def get(self, key: str) -> Approval | None:
        return self._approvals.get(key)

    def remove(self, key: str) -> None:
        self._approvals.pop(key, None)

    def clear(self) -> None:
        self._approvals.clear()
        self.last_reports.clear()

    def keys(self) -> t.KeysView[str]:
        return self._approvals.keys()


ApprovalRegistry = CapabilityRegistry

def diff_reports(
    old: CapabilityReport | Approval | None,
    new: CapabilityReport,
) -> CapabilityDiff:
    if isinstance(old, Approval):
        old = old.report

    if old is None:
        old_filter: dict[str, CallableBinding] = {}
        old_test: dict[str, CallableBinding] = {}
        old_global: dict[str, CallableBinding] = {}
        old_deps: tuple[str, ...] = ()
        source_changed = False
        overlay_changed = False
        old_key: str | None = None
    else:
        old_filter = old.filter_bindings
        old_test = old.test_bindings
        old_global = old.global_bindings
        old_deps = tuple(
            sorted(
                old.dependencies.filters
                | old.dependencies.tests
                | old.dependencies.globals
            )
        )
        source_changed = old.source_checksum != new.source_checksum
        overlay_changed = old.overlay.fingerprint != new.overlay.fingerprint
        old_key = old.key

    changed_filters = tuple(
        sorted(
            name
            for name in set(old_filter) | set(new.filter_bindings)
            if name in old_filter
            and name in new.filter_bindings
            and (
                not old_filter[name].matches(new.filter_bindings[name].obj)
                or old_filter[name].pass_arg
                != new.filter_bindings[name].pass_arg
            )
        )
    )
    changed_tests = tuple(
        sorted(
            name
            for name in set(old_test) | set(new.test_bindings)
            if name in old_test
            and name in new.test_bindings
            and (
                not old_test[name].matches(new.test_bindings[name].obj)
                or old_test[name].pass_arg
                != new.test_bindings[name].pass_arg
            )
        )
    )
    changed_globals = tuple(
        sorted(
            name
            for name in set(old_global) | set(new.global_bindings)
            if name in old_global
            and name in new.global_bindings
            and not old_global[name].matches(new.global_bindings[name].obj)
        )
    )

    new_deps = tuple(
        sorted(
            new.dependencies.filters
            | new.dependencies.tests
            | new.dependencies.globals
        )
    )
    added = tuple(sorted(set(new_deps) - set(old_deps)))
    removed = tuple(sorted(set(old_deps) - set(new_deps)))

    return CapabilityDiff(
        old_key=old_key,
        new_key=new.key,
        changed_filters=changed_filters,
        changed_tests=changed_tests,
        changed_globals=changed_globals,
        added=added,
        removed=removed,
        source_changed=source_changed,
        overlay_changed=overlay_changed,
    )


def make_overlay_info(environment: Environment) -> OverlayInfo:
    chain: list[str] = []
    current: t.Any = environment
    seen: set[int] = set()

    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(f"{type(current).__module__}.{type(current).__qualname__}")

        if not getattr(current, "overlayed", False):
            break

        current = getattr(current, "linked_to", None)

    digest = _sha256()
    digest.update(type(environment).__module__.encode())
    digest.update(b":")
    digest.update(type(environment).__qualname__.encode())
    for value in (
        bool(getattr(environment, "sandboxed", False)),
        getattr(environment, "is_async", False),
        getattr(environment, "optimized", False),
        getattr(environment, "overlayed", False),
        tuple(chain),
    ):
        _update_fingerprint(digest, value)

    autoescape = getattr(environment, "autoescape", False)
    if callable(autoescape):
        digest.update(implementation_fingerprint(autoescape).encode("ascii"))
    else:
        _update_fingerprint(digest, autoescape)

    return OverlayInfo(
        class_name=type(environment).__name__,
        chain=tuple(chain),
        sandboxed=bool(getattr(environment, "sandboxed", False)),
        is_async=bool(getattr(environment, "is_async", False)),
        optimized=bool(getattr(environment, "optimized", False)),
        fingerprint=digest.hexdigest(),
    )


def make_binding(
    kind: str,
    name: str,
    obj: t.Any,
    environment: Environment | None,
    origin: str,
) -> CallableBinding:
    if obj is None:
        implementation = "missing"
        fingerprint = "missing"
        safe = False
        pass_arg = None
    else:
        implementation = implementation_fingerprint(obj)
        fingerprint = callable_fingerprint(obj)
        pass_arg = pass_arg_name(obj)
        if environment is not None and hasattr(environment, "is_safe_callable"):
            safe = bool(environment.is_safe_callable(obj))
        else:
            safe = not (
                getattr(obj, "unsafe_callable", False)
                or getattr(obj, "alters_data", False)
            )

    return CallableBinding(
        name=name,
        kind=kind,
        fingerprint=fingerprint,
        implementation_fingerprint=implementation,
        pass_arg=pass_arg,
        safe=safe,
        origin=origin,
        obj=obj,
    )


def _expression_label(node: nodes.Node) -> str:
    if isinstance(node, nodes.Name):
        return node.name
    if isinstance(node, nodes.Getattr):
        return f"{_expression_label(node.node)}.{node.attr}"
    if isinstance(node, nodes.Getitem):
        return f"{_expression_label(node.node)}[...]"
    return type(node).__name__


def _template_references(ast: nodes.Template) -> tuple[TemplateReferenceCapability, ...]:
    refs: list[TemplateReferenceCapability] = []
    ref_types = (nodes.Extends, nodes.FromImport, nodes.Import, nodes.Include)
    kind_names = {
        nodes.Extends: "extends",
        nodes.FromImport: "from_import",
        nodes.Import: "import",
        nodes.Include: "include",
    }

    for node in ast.find_all(ref_types):  # type: ignore[arg-type]
        template = node.template
        names: list[str] = []
        dynamic = False
        name: str | None = None

        if isinstance(template, nodes.Const):
            if isinstance(template.value, str):
                name = template.value
                names.append(template.value)
            elif isinstance(template.value, (tuple, list)):
                names.extend(value for value in template.value if isinstance(value, str))
                dynamic = len(names) != len(template.value)
            else:
                dynamic = True
        elif isinstance(template, (nodes.Tuple, nodes.List)):
            for item in template.items:
                if isinstance(item, nodes.Const) and isinstance(item.value, str):
                    names.append(item.value)
                else:
                    dynamic = True
        else:
            dynamic = True

        refs.append(
            TemplateReferenceCapability(
                kind=kind_names.get(type(node), type(node).__name__.lower()),
                name=name,
                names=tuple(names),
                dynamic=dynamic,
                lineno=getattr(node, "lineno", None),
            )
        )

    return tuple(refs)


def _resolve_expression(
    node: nodes.Node,
    environment: Environment,
    context: t.Mapping[str, t.Any] | None,
) -> t.Any:
    if isinstance(node, nodes.Name):
        if context is not None and node.name in context:
            return context[node.name]
        return environment.globals.get(node.name)

    if isinstance(node, nodes.Getattr):
        obj = _resolve_expression(node.node, environment, context)
        if obj is None:
            return None
        value = environment.getattr(obj, node.attr)
        from .runtime import Undefined

        if isinstance(value, Undefined):
            return None
        return value

    if isinstance(node, nodes.Getitem):
        obj = _resolve_expression(node.node, environment, context)
        if obj is None or not isinstance(node.arg, nodes.Const):
            return None
        try:
            value = environment.getitem(obj, node.arg.value)
        except Exception:
            return None
        from .runtime import Undefined

        if isinstance(value, Undefined):
            return None
        return value

    return None


def collect_dependencies(
    environment: Environment,
    ast: nodes.Template,
    context: t.Mapping[str, t.Any] | None = None,
) -> tuple[
    CompiledDependencies,
    dict[str, CallableBinding],
    dict[str, CallableBinding],
    dict[str, CallableBinding],
]:
    filter_names = frozenset(node.name for node in ast.find_all(nodes.Filter))
    test_names = frozenset(node.name for node in ast.find_all(nodes.Test))

    try:
        undeclared = frozenset(meta.find_undeclared_variables(ast))
    except Exception:
        undeclared = frozenset()

    global_names = frozenset(
        node.name
        for node in ast.find_all(nodes.Name)
        if node.ctx == "load" and node.name in environment.globals
    )

    filter_bindings = {
        name: make_binding(
            "filter", name, environment.filters.get(name), environment, "environment.filters"
        )
        for name in filter_names
    }
    test_bindings = {
        name: make_binding(
            "test", name, environment.tests.get(name), environment, "environment.tests"
        )
        for name in test_names
    }
    global_bindings = {
        name: make_binding(
            "global", name, environment.globals.get(name), environment, "environment.globals"
        )
        for name in global_names
    }

    context_bindings: dict[str, CallableBinding] = {}
    dynamic_calls: list[DynamicCallCapability] = []

    for call in ast.find_all(nodes.Call):
        callee = call.node
        label = _expression_label(callee)
        name = callee.name if isinstance(callee, nodes.Name) else None
        resolved: t.Any = None
        origin = "dynamic"

        if name is not None:
            if context is not None and name in context:
                resolved = context[name]
                origin = "context"
            elif name in environment.globals:
                continue
            elif name not in undeclared and undeclared:
                dynamic_calls.append(
                    DynamicCallCapability(
                        description=f"{label}(...)",
                        kind="template_local",
                        name=name,
                        lineno=getattr(call, "lineno", None),
                        known=True,
                        reason="declared in template",
                    )
                )
                continue
            else:
                resolved = None
        else:
            resolved = _resolve_expression(callee, environment, context)
            origin = "runtime_expression"

        binding: CallableBinding | None = None
        known = False
        reason = "dynamic callee cannot be resolved statically"

        if resolved is not None and callable(resolved):
            binding = make_binding(
                "context-call", name or label, resolved, environment, origin
            )
            context_key = name or label
            context_bindings[context_key] = binding
            known = True
            reason = "resolved from pre-runtime context"
        elif resolved is not None:
            reason = "resolved value is not callable"
        elif context is not None and name is not None and name in context:
            reason = "context value is not callable"

        kind = "context_name" if name is not None else "dynamic_expression"
        dynamic_calls.append(
            DynamicCallCapability(
                description=f"{label}(...)",
                kind=kind,
                name=name,
                lineno=getattr(call, "lineno", None),
                known=known,
                reason=reason,
                binding=binding,
            )
        )

    dependencies = CompiledDependencies(
        filters=filter_names,
        tests=test_names,
        globals=global_names,
        undeclared_variables=frozenset(undeclared),
        template_references=_template_references(ast),
        dynamic_calls=tuple(dynamic_calls),
    )
    return (
        dependencies,
        filter_bindings,
        test_bindings,
        global_bindings,
        context_bindings,
    )


def report_fingerprint(
    source_checksum: str,
    overlay: OverlayInfo,
    dependencies: CompiledDependencies,
    filter_bindings: dict[str, CallableBinding],
    test_bindings: dict[str, CallableBinding],
    global_bindings: dict[str, CallableBinding],
    context_bindings: dict[str, CallableBinding],
) -> str:
    digest = _sha256()
    digest.update(b"capability-report-v1\0")
    digest.update(source_checksum.encode("ascii"))
    digest.update(overlay.fingerprint.encode("ascii"))

    for category, values in (
        ("filter-names", dependencies.filters),
        ("test-names", dependencies.tests),
        ("global-names", dependencies.globals),
        ("undeclared", dependencies.undeclared_variables),
    ):
        digest.update(category.encode())
        for value in sorted(values):
            _update_fingerprint(digest, value)

    for category, bindings in (
        ("filter", filter_bindings),
        ("test", test_bindings),
        ("global", global_bindings),
        ("context", context_bindings),
    ):
        for name in sorted(bindings):
            binding = bindings[name]
            digest.update(category.encode())
            _update_fingerprint(digest, name)
            digest.update(binding.fingerprint.encode("ascii"))
            digest.update(str(binding.pass_arg).encode())
            digest.update(str(binding.safe).encode())

    for ref in dependencies.template_references:
        _update_fingerprint(
            digest, (ref.kind, ref.name, ref.names, ref.dynamic, ref.lineno)
        )

    for call in dependencies.dynamic_calls:
        _update_fingerprint(
            digest,
            (
                call.description,
                call.kind,
                call.name,
                call.lineno,
                call.known,
                call.reason,
                call.binding.fingerprint if call.binding else "",
            ),
        )

    return digest.hexdigest()


class CapabilityAudit(dict):
    """Mapping of template keys to reports plus aggregate change lists."""

    def __init__(
        self,
        reports: t.Mapping[str, CapabilityReport],
        *,
        changed: t.Iterable[str] = (),
        stable: t.Iterable[str] = (),
        blocked: t.Iterable[str] = (),
    ) -> None:
        super().__init__(reports)
        self.changed: tuple[str, ...] = tuple(changed)
        self.stable: tuple[str, ...] = tuple(stable)
        self.blocked: tuple[str, ...] = tuple(blocked)
        self.review_required: tuple[str, ...] = tuple(
            key for key, report in reports.items() if report.requires_review
        )

    @property
    def affected_templates(self) -> tuple[str, ...]:
        return self.changed


class CapabilityGrant:
    """A verified report bound to the calls made during one render."""

    def __init__(
        self,
        reviewer: CapabilityReviewer,
        report: CapabilityReport,
        context: t.Mapping[str, t.Any] | None = None,
    ) -> None:
        self.reviewer = reviewer
        self.report = report
        self.context = dict(context or {})
        self.calls: list[dict[str, t.Any]] = []
        self.templates: list[str] = []
        self.allowed_fingerprints = {
            binding.fingerprint for binding in report.bindings if binding.obj is not None
        }
        self.allowed_templates = {
            name
            for ref in report.template_references
            for name in ref.names
        }
        if report.name:
            self.allowed_templates.add(report.name)
        record = reviewer.registry.get(report.key)
        self.allow_unknown_calls = bool(
            reviewer.allow_unknown_dynamic_calls
            or (record is not None and record.allowed_unknown)
        )

    def verify(self) -> None:
        self.reviewer.verify_bindings(self.report, self.context)

    def authorize_call(self, obj: t.Any, description: str | None = None) -> t.Any:
        original = getattr(obj, "__capability_original__", obj)
        fingerprint = callable_fingerprint(original) if original is not None else ""

        if fingerprint in self.allowed_fingerprints:
            self.calls.append({"description": description, "fingerprint": fingerprint})
            return original

        environment = self.reviewer.environment
        safe_environment = environment is not None
        is_safe = safe_environment and hasattr(environment, "is_safe_callable") and environment.is_safe_callable(original)
        if self.allow_unknown_calls and is_safe:
            self.calls.append(
                {
                    "description": description,
                    "fingerprint": fingerprint,
                    "runtime_approved": True,
                }
            )
            return original

        if (
            self.reviewer.runtime_safe_calls
            and is_safe
            and hasattr(environment, "is_safe_callable")
        ):
            self.calls.append(
                {
                    "description": description,
                    "fingerprint": fingerprint,
                    "runtime_safe": True,
                }
            )
            return original

        if self.allow_unknown_calls and not safe_environment:
            return original

        raise UnknownDynamicCallError(
            f"Dynamic call {description or _expression_label(type('N', (), {'name': None})())!r} "
            "is not bound to the approved capability report.",
            review=self.report,
        )

    def authorize_template_name(self, name: str) -> None:
        self.templates.append(name)
        if name in self.allowed_templates:
            return

        # A dynamic reference was explicitly present in the report. Resolving
        # it here is the late binding point; recursive approval is opt-in.
        if self.report.lazy_references:
            if self.reviewer.recursive_templates:
                self.reviewer.require(name)
            return

        if not self.reviewer.strict_template_names:
            return

        raise CapabilityReviewRequired(
            f"Template reference {name!r} is not in the approved capability report.",
            review=self.report,
        )

    def __enter__(self) -> CapabilityGrant:
        self._token = ACTIVE_GRANT.set(self)
        return self

    def __exit__(self, exc_type: t.Any, exc: t.Any, tb: t.Any) -> None:
        token = getattr(self, "_token", None)
        if token is not None:
            ACTIVE_GRANT.reset(token)


class CapabilityReviewer:
    """Review and approve effective sandbox capabilities for templates."""

    def __init__(
        self,
        environment: Environment | None = None,
        registry: CapabilityRegistry | None = None,
        *,
        allow_unknown_dynamic_calls: bool = False,
        allow_lazy_templates: bool = True,
        allow_unsafe_callables: bool = False,
        recursive_templates: bool = False,
        runtime_safe_calls: bool = False,
        strict_template_names: bool = False,
    ) -> None:
        self.environment = environment
        if registry is None and environment is not None:
            registry = getattr(environment, "capability_registry", None)
        self.registry = registry or CapabilityRegistry()
        self.allow_unknown_dynamic_calls = allow_unknown_dynamic_calls
        self.allow_lazy_templates = allow_lazy_templates
        self.allow_unsafe_callables = allow_unsafe_callables
        self.recursive_templates = recursive_templates
        self.runtime_safe_calls = runtime_safe_calls
        self.strict_template_names = strict_template_names
        self._sources: dict[str, str] = {}
        self._last_reports: dict[str, CapabilityReport] = {}

    def review(
        self,
        target: t.Any = None,
        *,
        source: str | None = None,
        name: str | None = None,
        filename: str | None = None,
        ast: nodes.Template | None = None,
        template: t.Any = None,
        context: t.Mapping[str, t.Any] | None = None,
        environment: Environment | None = None,
        allow_unknown_dynamic_calls: bool | None = None,
        strict_lazy_templates: bool | None = None,
    ) -> CapabilityReport:
        env = environment or self.environment
        if env is None:
            raise CapabilityError("A Jinja environment is required for capability review.")
        if target is None and template is not None:
            target = template

        source_checksum = ""
        cache_key = None

        if ast is not None:
            name = getattr(ast, "name", name)
            key = name or "<ast>"
        else:
            source, name, filename, ast = self._load_input(
                env, target, source=source, name=name, filename=filename
            )
            source_checksum = hashlib.sha256(source.encode("utf-8")).hexdigest()
            key = name or f"<string:{source_checksum[:16]}>"
            self._sources[key] = source

        if name is not None and getattr(env, "bytecode_cache", None) is not None:
            try:
                cache_key = env.bytecode_cache.get_cache_key(name, filename)
            except Exception:
                cache_key = None

        dependencies, filters, tests, globals_, context_bindings = collect_dependencies(
            env, ast, context
        )
        overlay = make_overlay_info(env)
        fingerprint = report_fingerprint(
            source_checksum,
            overlay,
            dependencies,
            filters,
            tests,
            globals_,
            context_bindings,
        )
        report = CapabilityReport(
            key=key,
            name=name,
            source_checksum=source_checksum,
            overlay=overlay,
            dependencies=dependencies,
            fingerprint=fingerprint,
            filename=filename,
            cache_key=cache_key,
            filter_bindings=filters,
            test_bindings=tests,
            global_bindings=globals_,
            context_bindings=context_bindings,
            reviewer=self,
        )
        reviewed = self._with_approval(
            report,
            allow_unknown=allow_unknown_dynamic_calls,
            strict_lazy=strict_lazy_templates,
        )
        self.registry.remember(reviewed)
        self._last_reports[reviewed.key] = reviewed
        return reviewed

    def review_template(self, name: str, **kwargs: t.Any) -> CapabilityReport:
        return self.review(name=name, **kwargs)

    def review_source(self, source: str, name: str | None = None, **kwargs: t.Any) -> CapabilityReport:
        return self.review(source=source, name=name, **kwargs)

    review_string = review_source
    review_capabilities = review
    collect = review

    def _load_input(
        self,
        env: Environment,
        target: t.Any,
        *,
        source: str | None,
        name: str | None,
        filename: str | None,
    ) -> tuple[str, str | None, str | None, nodes.Template]:
        if source is not None:
            return source, name, filename, env.parse(source, name, filename)

        if target is not None and not isinstance(target, str):
            target_env = getattr(target, "environment", None)
            if target_env is not None:
                env = target_env
            target_name = getattr(target, "name", None)
            if target_name is not None and getattr(env, "loader", None) is not None:
                loaded_source, loaded_filename, _ = env.loader.get_source(env, target_name)
                return loaded_source, target_name, loaded_filename, env.parse(
                    loaded_source, target_name, loaded_filename
                )
            raise CapabilityError("A template object without a loader source cannot be reviewed.")

        if isinstance(target, str):
            if target in self._sources:
                source = self._sources[target]
                return source, target, filename, env.parse(source, target, filename)

            if source is None and name is None and getattr(env, "loader", None) is not None:
                try:
                    loaded_source, loaded_filename, _ = env.loader.get_source(env, target)
                    return loaded_source, target, loaded_filename, env.parse(
                        loaded_source, target, loaded_filename
                    )
                except Exception:
                    source = target
            elif source is None:
                source = target

        if name is not None and source is None and getattr(env, "loader", None) is not None:
            loaded_source, loaded_filename, _ = env.loader.get_source(env, name)
            return loaded_source, name, loaded_filename, env.parse(
                loaded_source, name, loaded_filename
            )

        if source is None:
            raise CapabilityError("Provide template source, a template name, or a template object.")

        return source, name, filename, env.parse(source, name, filename)

    def _with_approval(
        self,
        report: CapabilityReport,
        *,
        allow_unknown: bool | None,
        strict_lazy: bool | None,
    ) -> CapabilityReport:
        approval = self.registry.get(report.key)
        baseline = (
            approval.report
            if approval is not None
            else self.registry.last_report(report.key)
        )
        diff = diff_reports(baseline, report)
        reasons: list[str] = []

        missing = [
            binding.name
            for binding in report.bindings
            if binding.fingerprint == "missing"
        ]
        unsafe = [
            binding.name
            for binding in report.bindings
            if not binding.safe and binding.fingerprint != "missing"
        ]
        if missing:
            reasons.append(f"missing callable capabilities: {', '.join(sorted(missing))}")
        if unsafe and not self.allow_unsafe_callables:
            reasons.append(f"unsafe callable capabilities: {', '.join(sorted(unsafe))}")

        unknown = report.unknown_dynamic_calls
        old_allows_unknown = bool(approval is not None and approval.allowed_unknown)
        old_allows_unsafe = bool(approval is not None and approval.allowed_unsafe)
        unknown_allowed = (
            self.allow_unknown_dynamic_calls if allow_unknown is None else allow_unknown
        ) or old_allows_unknown
        unsafe_allowed = self.allow_unsafe_callables or old_allows_unsafe

        if unknown and not unknown_allowed:
            reasons.append(
                f"{len(unknown)} unrecognized dynamic call(s) require capability binding"
            )

        lazy_strict = False if strict_lazy is None else strict_lazy
        if lazy_strict and report.lazy_references and not self.allow_lazy_templates:
            reasons.append("lazy template reference cannot be resolved before runtime")

        status = "review_required"
        if missing or (unsafe and not unsafe_allowed):
            status = "blocked"
        elif reasons:
            status = "unknown"
        elif approval is not None and approval.fingerprint == report.fingerprint:
            status = "approved"

        approved = status == "approved"
        return replace(
            report,
            status=status,
            approved=approved,
            approved_fingerprint=approval.fingerprint if approval is not None else None,
            changed_filters=diff.changed_filters,
            changed_tests=diff.changed_tests,
            changed_globals=diff.changed_globals,
            added_dependencies=diff.added,
            removed_dependencies=diff.removed,
            block_reasons=tuple(reasons),
        )

    def approve(
        self,
        target: t.Any = None,
        *,
        report: CapabilityReport | None = None,
        force: bool = False,
        allow_unknown_dynamic_calls: bool | None = None,
        allow_unsafe_callables: bool | None = None,
        note: str | None = None,
        context: t.Mapping[str, t.Any] | None = None,
        **kwargs: t.Any,
    ) -> CapabilityReport:
        if report is None:
            report = self.review(target, context=context, **kwargs)

        allow_unknown = force or (
            self.allow_unknown_dynamic_calls
            if allow_unknown_dynamic_calls is None
            else allow_unknown_dynamic_calls
        )
        allow_unsafe = force or (
            self.allow_unsafe_callables
            if allow_unsafe_callables is None
            else allow_unsafe_callables
        )

        missing = [b for b in report.bindings if b.fingerprint == "missing"]
        unsafe = [
            b
            for b in report.bindings
            if not b.safe and b.fingerprint != "missing"
        ]
        if missing:
            raise CapabilityReviewRequired(review=report)
        if report.unknown_dynamic_calls and not allow_unknown:
            raise UnknownDynamicCallError(review=report)
        current_unsafe_allowed = allow_unsafe or bool(
            self.registry.get(report.key) is not None
            and self.registry.get(report.key).allowed_unsafe
        )
        if unsafe and not current_unsafe_allowed:
            raise CapabilityError("Report contains unsafe callable capabilities.", report)

        approved = self.registry.approve(
            report,
            note=note,
            allowed_unknown=allow_unknown,
            allowed_unsafe=allow_unsafe,
        ).report
        return approved

    def is_approved(self, target: t.Any = None, **kwargs: t.Any) -> bool:
        report = target if isinstance(target, CapabilityReport) else self.review(target, **kwargs)
        record = self.registry.get(report.key)
        return bool(record is not None and record.fingerprint == report.fingerprint)

    can_use = is_approved

    def require(
        self,
        target: t.Any = None,
        *,
        context: t.Mapping[str, t.Any] | None = None,
        **kwargs: t.Any,
    ) -> CapabilityGrant:
        approval_report = self.review(target, **kwargs)
        if not self.is_approved(approval_report):
            if approval_report.unknown_dynamic_calls:
                raise UnknownDynamicCallError(review=approval_report)
            raise CapabilityReviewRequired(review=approval_report)

        bound_report = approval_report
        if context:
            bound_report = self.review(target, context=context, **kwargs)
        self.verify_bindings(bound_report, context or {})
        return CapabilityGrant(self, bound_report, context)

    def verify_bindings(
        self,
        report: CapabilityReport,
        context: t.Mapping[str, t.Any] | None = None,
    ) -> bool:
        env = self.environment
        if env is None:
            raise CapabilityError("An environment is required to verify bindings.", report)

        maps = (
            ("filter", report.filter_bindings, env.filters),
            ("test", report.test_bindings, env.tests),
            ("global", report.global_bindings, env.globals),
        )
        for kind, bindings, values in maps:
            for name, binding in bindings.items():
                current = values.get(name)
                if not binding.matches(current):
                    raise StaleCapabilityError(
                        f"The approved {kind} {name!r} implementation changed.", report
                    )

        context = context or {}
        for name, binding in report.context_bindings.items():
            if binding.kind != "context":
                continue
            current = context.get(name)
            if not binding.matches(current):
                raise StaleCapabilityError(
                    f"The pre-runtime context callable {name!r} changed.", report
                )

        return True

    def recheck_all(self, targets: t.Iterable[t.Any] | None = None) -> CapabilityAudit:
        if targets is None:
            keys = tuple(self.registry.keys())
        else:
            keys = tuple(targets)

        reports: dict[str, CapabilityReport] = {}
        changed: list[str] = []
        stable: list[str] = []
        blocked: list[str] = []

        for key in keys:
            old = self.registry.get(key) if isinstance(key, str) else None
            old_report = old.report if old is not None else None
            target: t.Any = key
            kwargs: dict[str, t.Any] = {}

            if old_report is not None:
                if old_report.name is not None and self.environment is not None and self.environment.loader is not None:
                    target = old_report.name
                elif key in self._sources:
                    target = self._sources[key]
                    kwargs["name"] = old_report.name

            report = self.review(target, **kwargs)
            reports[report.name or report.key] = report
            audit_key = report.name or report.key
            if old is not None and old.fingerprint == report.fingerprint and report.approved:
                stable.append(audit_key)
            else:
                changed.append(audit_key)
            if report.blocked or report.status == "unknown":
                blocked.append(audit_key)

        return CapabilityAudit(reports, changed=changed, stable=stable, blocked=blocked)

    review_all = recheck_all
    audit = recheck_all

    def render(
        self,
        target: t.Any = None,
        *args: t.Any,
        context: t.Mapping[str, t.Any] | None = None,
        environment: Environment | None = None,
        **kwargs: t.Any,
    ) -> t.Any:
        env = environment or self.environment
        if env is None:
            raise CapabilityError("An environment is required to render a template.")

        variables: dict[str, t.Any] = {}
        for arg in args:
            if isinstance(arg, t.Mapping):
                variables.update(arg)
        if context:
            variables.update(context)
        variables.update(kwargs)

        grant = self.require(target, context=variables, environment=env)
        token = ACTIVE_GRANT.set(grant)
        try:
            template = self._template_for_render(target, grant.report, env)
            return template.render(variables)
        finally:
            ACTIVE_GRANT.reset(token)

    def _template_for_render(
        self,
        target: t.Any,
        report: CapabilityReport,
        env: Environment,
    ) -> t.Any:
        if target is not None and not isinstance(target, str):
            return target

        source = self._sources.get(report.key)
        if report.name is not None and getattr(env, "loader", None) is not None:
            try:
                return env.get_template(report.name)
            except Exception:
                if source is None:
                    raise
        if source is not None:
            return env.from_string(source)
        if isinstance(target, str):
            return env.from_string(target)
        raise CapabilityError("Unable to resolve template for reviewed capability report.", report)


CapabilityGate = CapabilityReviewer


def review_template_capabilities(
    source_or_environment: t.Any = None,
    environment_or_source: t.Any = None,
    *args: t.Any,
    **kwargs: t.Any,
) -> CapabilityReport:
    if hasattr(source_or_environment, "parse") and hasattr(source_or_environment, "filters"):
        environment = source_or_environment
        target = environment_or_source
    else:
        target = source_or_environment
        environment = environment_or_source
    reviewer = getattr(environment, "capability_reviewer", None)
    if not isinstance(reviewer, CapabilityReviewer):
        reviewer = CapabilityReviewer(environment)
    return reviewer.review(target, *args, **kwargs)


def approve_capabilities(
    report_or_environment: t.Any = None,
    target: t.Any = None,
    **kwargs: t.Any,
) -> CapabilityReport:
    if isinstance(report_or_environment, CapabilityReport):
        return report_or_environment.approve(**kwargs)

    environment = report_or_environment
    reviewer = getattr(environment, "capability_reviewer", None)
    if not isinstance(reviewer, CapabilityReviewer):
        reviewer = CapabilityReviewer(environment)
    return reviewer.approve(target, **kwargs)


def recheck_capabilities(
    reviewer_or_environment: t.Any = None,
    targets: t.Iterable[t.Any] | None = None,
    **kwargs: t.Any,
) -> CapabilityAudit:
    if isinstance(reviewer_or_environment, CapabilityReviewer):
        reviewer = reviewer_or_environment
    else:
        reviewer = getattr(reviewer_or_environment, "capability_reviewer", None)
        if not isinstance(reviewer, CapabilityReviewer):
            reviewer = CapabilityReviewer(reviewer_or_environment)
    return reviewer.recheck_all(targets, **kwargs)


def render_reviewed(
    environment: Environment, target: t.Any = None, *args: t.Any, **kwargs: t.Any
) -> str:
    reviewer = getattr(environment, "capability_reviewer", None)
    if not isinstance(reviewer, CapabilityReviewer):
        reviewer = CapabilityReviewer(environment)
    return reviewer.render(target, *args, **kwargs)


review_capabilities = review_template_capabilities
review_sandbox_template = review_template_capabilities
audit_capabilities = review_template_capabilities


class MemoryBytecodeCache(BytecodeCache):
    """Small in-process bytecode cache used by tests and embedded callers."""

    def __init__(self) -> None:
        self.values: dict[str, bytes] = {}

    def load_bytecode(self, bucket: t.Any) -> None:
        data = self.values.get(bucket.key)
        if data is not None:
            bucket.bytecode_from_string(data)

    def dump_bytecode(self, bucket: t.Any) -> None:
        out = BytesIO()
        bucket.write_bytecode(out)
        self.values[bucket.key] = out.getvalue()

    def clear(self) -> None:
        self.values.clear()


DictBytecodeCache = MemoryBytecodeCache


class CapabilityBytecodeCache(BytecodeCache):
    """Gate a shared bytecode cache through a capability registry."""

    def __init__(
        self,
        cache: BytecodeCache | None = None,
        reviewer: CapabilityReviewer | None = None,
        registry: CapabilityRegistry | None = None,
        *,
        require_approval: bool = True,
        on_stale: str = "raise",
    ) -> None:
        self.cache = cache or MemoryBytecodeCache()
        self.registry = registry or CapabilityRegistry()
        self.reviewer = reviewer
        self.require_approval = require_approval
        self.on_stale = on_stale
        self.last_report: CapabilityReport | None = None

    def _reviewer(self, environment: Environment) -> CapabilityReviewer:
        if self.reviewer is not None:
            return self.reviewer
        return CapabilityReviewer(environment, registry=self.registry)

    def load_bytecode(self, bucket: t.Any) -> None:
        self.cache.load_bytecode(bucket)

    def dump_bytecode(self, bucket: t.Any) -> None:
        self.cache.dump_bytecode(bucket)

    def clear(self) -> None:
        self.cache.clear()

    def get_bucket(
        self,
        environment: Environment,
        name: str,
        filename: str | None,
        source: str,
    ) -> t.Any:
        bucket = self.cache.get_bucket(environment, name, filename, source)
        reviewer = self._reviewer(environment)
        report = reviewer.review(
            source=source, name=name, filename=filename, environment=environment
        )
        self.last_report = report

        if self.require_approval and not reviewer.is_approved(report):
            if self.on_stale == "reset":
                bucket.reset()
            else:
                raise CapabilityReviewRequired(review=report)

        return bucket


ReviewingBytecodeCache = CapabilityBytecodeCache
CapabilityAwareBytecodeCache = CapabilityBytecodeCache
SecureBytecodeCache = CapabilityBytecodeCache
SharedCapabilityBytecodeCache = CapabilityBytecodeCache
ReviewedBytecodeCache = CapabilityBytecodeCache


def review_bytecode_cache(
    cache: BytecodeCache | None = None, **kwargs: t.Any
) -> CapabilityBytecodeCache:
    return CapabilityBytecodeCache(cache, **kwargs)


class BoundOverlay:
    """An overlay plus the grant that authorizes its runtime calls."""

    def __init__(
        self,
        overlay: Environment,
        grant: CapabilityGrant,
        report: CapabilityReport,
    ) -> None:
        self.environment = overlay
        self.overlay = overlay
        self.grant = grant
        self.report = report

    def render(self, *args: t.Any, **kwargs: t.Any) -> str:
        with self.grant:
            template = self.overlay.get_template(self.report.name)
            return template.render(*args, **kwargs)


SandboxCapabilityReviewer = CapabilityReviewer
TemplateCapabilityReviewer = CapabilityReviewer
CapabilityVerifier = CapabilityReviewer
CapabilityAuditor = CapabilityReviewer
ReviewGate = CapabilityReviewer
CapabilityEntry = CapabilityReviewer


def review_sandbox_capabilities(
    environment: Environment, target: t.Any = None, **kwargs: t.Any
) -> CapabilityReport:
    return CapabilityReviewer(environment).review(target, **kwargs)


def verify_capabilities(
    environment: Environment, target: t.Any = None, **kwargs: t.Any
) -> CapabilityReport:
    reviewer = CapabilityReviewer(environment)
    report = reviewer.review(target, **kwargs)
    if not report.approved:
        raise CapabilityReviewRequired(review=report)
    return report


def bind_compiled_dependencies(
    environment: Environment, target: t.Any = None, **kwargs: t.Any
) -> CapabilityGrant:
    return CapabilityReviewer(environment).require(target, **kwargs)


def _reviewer_recompile(self: CapabilityReviewer, target: t.Any = None, **kwargs: t.Any) -> t.Any:
    report = self.review(target, **kwargs)
    env = self.environment

    if env is None:
        raise CapabilityError("An environment is required to recompile a template.", report)

    source = self._sources.get(report.key)
    filename = report.filename

    if source is None and report.name is not None and getattr(env, "loader", None) is not None:
        source, filename, _ = env.loader.get_source(env, report.name)

    if source is None and isinstance(target, str):
        source = target

    if source is None:
        raise CapabilityError("No source is available to recompile template.", report)

    code = env.compile(source, report.name, filename)
    cache = getattr(env, "bytecode_cache", None)

    if cache is not None and report.name is not None:
        bucket = cache.get_bucket(env, report.name, filename, source)
        bucket.code = code
        cache.set_bucket(bucket)

    local_cache = getattr(env, "cache", None)
    mapping = getattr(local_cache, "_mapping", None)

    if mapping is not None and report.name is not None:
        for key in list(mapping):
            if isinstance(key, tuple) and len(key) == 2 and key[1] == report.name:
                try:
                    local_cache.pop(key, None)
                except Exception:
                    mapping.pop(key, None)

    return code


def _reviewer_reload_template(self: CapabilityReviewer, target: t.Any = None, **kwargs: t.Any) -> t.Any:
    report = self.review(target, **kwargs)
    self.recompile(report, **kwargs)
    env = self.environment

    if env is None:
        raise CapabilityError("An environment is required to reload a template.", report)

    if report.name is not None and getattr(env, "loader", None) is not None:
        return env.get_template(report.name)

    source = self._sources.get(report.key)
    if source is not None:
        return env.from_string(source)

    raise CapabilityError("Unable to reload template.", report)


def _reviewer_bind_overlay(
    self: CapabilityReviewer,
    target: t.Any = None,
    *,
    report: CapabilityReport | None = None,
    context: t.Mapping[str, t.Any] | None = None,
    wrap: bool = True,
    **kwargs: t.Any,
) -> BoundOverlay:
    if report is None:
        grant = self.require(target, context=context, **kwargs)
    else:
        self.verify_bindings(report, context or {})
        grant = CapabilityGrant(self, report, context)

    env = self.environment
    if env is None:
        raise CapabilityError("An environment is required to create an overlay.", report)

    overlay = env.overlay()
    overlay.filters = dict(overlay.filters)
    overlay.tests = dict(overlay.tests)
    overlay.globals = dict(overlay.globals)

    if wrap:
        for binding_report, mapping_name in (
            (grant.report.filter_bindings, "filters"),
            (grant.report.test_bindings, "tests"),
            (grant.report.global_bindings, "globals"),
        ):
            mapping = getattr(overlay, mapping_name)
            for name, binding in binding_report.items():
                original = binding.obj
                if original is None or not callable(original):
                    continue

                def make_wrapper(
                    original: t.Callable[..., t.Any] = original,
                    capability_name: str = name,
                    capability_kind: str = binding.kind,
                ) -> t.Callable[..., t.Any]:
                    @wraps(original)
                    def wrapper(*args: t.Any, **call_kwargs: t.Any) -> t.Any:
                        grant.authorize_call(
                            original, f"{capability_kind}:{capability_name}"
                        )
                        return original(*args, **call_kwargs)

                    wrapper.__capability_original__ = original  # type: ignore[attr-defined]
                    return wrapper

                mapping[name] = make_wrapper()

    return BoundOverlay(overlay, grant, grant.report)


CapabilityReviewer.recompile = _reviewer_recompile  # type: ignore[attr-defined]
CapabilityReviewer.reload_template = _reviewer_reload_template  # type: ignore[attr-defined]
CapabilityReviewer.bind_overlay = _reviewer_bind_overlay  # type: ignore[attr-defined]
CapabilityReviewer.bind_runtime_calls = CapabilityReviewer.require


def bind_overlay(
    environment: Environment, target: t.Any = None, **kwargs: t.Any
) -> BoundOverlay:
    return CapabilityReviewer(environment).bind_overlay(target, **kwargs)
