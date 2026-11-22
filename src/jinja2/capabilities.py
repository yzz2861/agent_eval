"""Capability bookkeeping for sandboxed templates."""

from __future__ import annotations

import functools
import hashlib
import types
import typing as t
from dataclasses import dataclass
from dataclasses import field

MISSING_FINGERPRINT = "<missing>"


def _code_fingerprint(code: types.CodeType) -> str:
    pieces: list[str] = [code.co_code.hex(), repr(code.co_names)]
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            pieces.append(_code_fingerprint(const))
        else:
            pieces.append(repr(const))
    return hashlib.sha1("\0".join(pieces).encode("utf-8")).hexdigest()


def _closure_fingerprint(func: t.Any) -> str:
    closure = getattr(func, "__closure__", None)
    if not closure:
        return ""
    values: list[str] = []
    for cell in closure:
        try:
            value = cell.cell_contents
        except ValueError:
            values.append("<empty>")
            continue
        try:
            if isinstance(value, (types.FunctionType, types.MethodType)):
                values.append(fingerprint(value))
            elif isinstance(value, (str, bytes, int, float, bool, type(None))):
                values.append(repr(value))
            else:
                values.append(f"{type(value).__qualname__}:{id(value)}")
        except Exception:
            values.append(f"{type(value).__qualname__}:{id(value)}")
    return hashlib.sha1("\0".join(values).encode("utf-8")).hexdigest()


def fingerprint(value: t.Any) -> str:
    """Return a stable description of the binding for value."""
    if value is None:
        return MISSING_FINGERPRINT
    if isinstance(value, functools.partial):
        return (
            "partial:"
            f"{fingerprint(value.func)}:"
            f"{repr(value.args)}:"
            f"{repr(sorted(value.keywords.items()))}"
        )
    if isinstance(value, types.MethodType):
        owner = value.__self__
        try:
            owner_fp = fingerprint(owner)
        except Exception:
            owner_fp = f"{type(owner).__qualname__}:{id(owner)}"
        return f"method:{fingerprint(value.__func__)}:{owner_fp}"
    if isinstance(value, types.FunctionType):
        return (
            "function:"
            f"{value.__module__}:"
            f"{value.__qualname__}:"
            f"{_code_fingerprint(value.__code__)}:"
            f"{_closure_fingerprint(value)}"
        )
    if isinstance(value, (types.BuiltinFunctionType, types.BuiltinMethodType)):
        name = getattr(value, "__qualname__", getattr(value, "__name__", ""))
        return f"builtin:{getattr(value, '__module__', '')}:{name}"
    if isinstance(value, type):
        return f"type:{value.__module__}:{value.__qualname__}"
    if callable(value):
        try:
            call = type(value).__call__
        except AttributeError:
            call = None
        call_fp = ""
        if call is not None:
            try:
                call_fp = fingerprint(call)
            except Exception:
                call_fp = type(call).__qualname__
        return (
            "callable:"
            f"{type(value).__module__}:"
            f"{type(value).__qualname__}:"
            f"{call_fp}:{id(value)}"
        )
    try:
        rendered = repr(value)
    except Exception:
        rendered = object.__repr__(value)
    digest = hashlib.sha1(rendered.encode("utf-8", "replace")).hexdigest()
    return f"value:{type(value).__module__}:{type(value).__qualname__}:{digest}"


class CapabilityChangeList(list):
    """A list of capability changes that also behaves as a boolean."""

    def __bool__(self) -> bool:
        return bool(len(self))

    def __eq__(self, other: object) -> bool:
        if isinstance(other, bool):
            return bool(self) is other
        return super().__eq__(other)

    def __contains__(self, item: object) -> bool:
        if isinstance(item, str):
            return any(item in (cap.key, cap.name, str(cap)) for cap in self)
        return super().__contains__(item)

    __hash__ = None  # type: ignore[assignment]


@dataclass(frozen=True, eq=False)
class Capability:
    """One resource used by a template."""

    kind: str
    name: str
    fingerprint: str | None = None
    current: str | None = None
    approved: bool = False
    deferred: bool = False
    optional: bool = False
    detail: str = ""

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.name}"

    @property
    def changed(self) -> bool:
        return (
            self.fingerprint is not None
            and self.current is not None
            and self.fingerprint != self.current
        )

    @property
    def missing(self) -> bool:
        return self.current == MISSING_FINGERPRINT

    def __str__(self) -> str:
        return self.key

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            return other in (self.key, self.name)
        if isinstance(other, Capability):
            return (
                self.kind,
                self.name,
                self.fingerprint,
                self.current,
                self.deferred,
            ) == (
                other.kind,
                other.name,
                other.fingerprint,
                other.current,
                other.deferred,
            )
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.kind, self.name, self.fingerprint, self.current))


class CapabilityManifest(dict[str, t.Any]):
    """The dependencies embedded in compiled template code."""

    def __init__(
        self,
        data: t.Mapping[str, t.Any] | None = None,
        *,
        template_name: str | None = None,
    ) -> None:
        super().__init__(data or {})
        self.setdefault("version", 1)
        self.template_name = template_name

    @property
    def filters(self) -> dict[str, str]:
        return self.get("filters", {})

    @property
    def tests(self) -> dict[str, str]:
        return self.get("tests", {})

    @property
    def globals(self) -> dict[str, str]:
        return self.get("globals", {})

    @property
    def templates(self) -> list[str]:
        return list(self.get("templates", ()))

    @property
    def dynamic_templates(self) -> list[str]:
        return list(self.get("dynamic_templates", ()))

    @property
    def has_dynamic_calls(self) -> bool:
        return bool(self.get("dynamic_calls", False))

    @property
    def dynamic_calls(self) -> bool:
        return self.has_dynamic_calls

    def iter_capabilities(self) -> t.Iterator[Capability]:
        for name, fp in sorted(self.filters.items()):
            yield Capability("filter", name, fp)
        for name, fp in sorted(self.tests.items()):
            yield Capability("test", name, fp)
        for name, fp in sorted(self.globals.items()):
            yield Capability("global", name, fp)
        for name in self.templates:
            yield Capability("template", name)
        for kind in self.dynamic_templates:
            yield Capability("template", kind, deferred=True)

    def signature(self) -> str:
        payload = repr(sorted((str(k), repr(v)) for k, v in self.items()))
        return hashlib.sha1(payload.encode("utf-8")).hexdigest()

    def __repr__(self) -> str:
        return dict.__repr__(self)


@dataclass
class CapabilityApproval:
    """A snapshot of an approved manifest and its concrete bindings."""

    template_name: str | None
    manifest_signature: str
    bindings: dict[str, dict[str, str | None]] = field(default_factory=dict)
    enforce_dynamic: bool = False
    explicit: bool = False
    dynamic_calls: dict[str, str] = field(default_factory=dict)

    def signature(self) -> str:
        payload = repr(
            sorted((key, repr(value)) for key, value in self.bindings.items())
        )
        return hashlib.sha1(payload.encode("utf-8")).hexdigest()

    def is_current(self, bindings: dict[str, dict[str, str | None]]) -> bool:
        return self.bindings == bindings


class CapabilityReview:
    """The result passed to a capability reviewer before a template runs."""

    def __init__(
        self,
        environment: t.Any,
        template: t.Any,
        manifest: CapabilityManifest,
        current: dict[str, dict[str, str | None]],
        capabilities: list[Capability],
    ) -> None:
        self.environment = environment
        self.template = template
        self.manifest = manifest
        self.template_name = getattr(template, "name", None)
        self.current = current
        self.capabilities = capabilities
        self.changed = CapabilityChangeList(c for c in capabilities if c.changed)
        self.missing = CapabilityChangeList(c for c in capabilities if c.missing)
        self.deferred = CapabilityChangeList(c for c in capabilities if c.deferred)
        self.denied = CapabilityChangeList()
        self.notes: list[str] = []
        self.approved = not self.changed and not self.missing

    @property
    def changed_capabilities(self) -> CapabilityChangeList:
        return self.changed

    @property
    def changes(self) -> CapabilityChangeList:
        return self.changed

    @property
    def unresolved(self) -> CapabilityChangeList:
        return self.deferred

    @property
    def pending(self) -> CapabilityChangeList:
        pending = CapabilityChangeList(
            capability for capability in self.changed if not capability.approved
        )
        pending.extend(
            capability
            for capability in self.missing
            if capability not in pending and not capability.approved
        )
        for capability in self.capabilities:
            if (
                not capability.approved
                and capability not in pending
                and not capability.deferred
            ):
                pending.append(capability)
        return pending

    @property
    def requires_review(self) -> bool:
        return bool(self.pending)

    @property
    def requires_approval(self) -> bool:
        return self.requires_review

    @property
    def ok(self) -> bool:
        return self.approved

    @property
    def is_approved(self) -> bool:
        return self.approved

    @property
    def reviewed(self) -> bool:
        return self.approved

    def approve(self, *items: t.Any) -> None:
        if not items:
            for capability in self.capabilities:
                object.__setattr__(capability, "approved", True)
            self.approved = True
            self.notes.append("all capabilities approved")
            return
        names = {_capability_name(item) for item in items}
        for capability in self.capabilities:
            if capability.key in names or capability.name in names:
                object.__setattr__(capability, "approved", True)
        self.approved = not self.pending
        self.notes.append(f"approved: {chr(44).join(sorted(names))}")

    def deny(self, *items: t.Any) -> None:
        if not items:
            self.approved = False
            self.denied = CapabilityChangeList(self.capabilities)
            self.notes.append("all capabilities denied")
            return
        names = {_capability_name(item) for item in items}
        for capability in self.capabilities:
            if capability.key in names or capability.name in names:
                self.denied.append(capability)
        self.approved = False
        self.notes.append(f"denied: {chr(44).join(sorted(names))}")

    def raise_if_denied(self) -> None:
        from .exceptions import CapabilityReviewRequired

        if not self.approved:
            detail = chr(44).join(cap.key for cap in (self.denied or self.pending))
            raise CapabilityReviewRequired(
                "capability review for template"
                f" {self.template_name!r} was not approved"
                + (f": {detail}" if detail else "")
            )

    def __bool__(self) -> bool:
        return self.approved

    def __repr__(self) -> str:
        return (
            f"<{type(self).__name__} template={self.template_name!r}"
            f" approved={self.approved!r} changed={[c.key for c in self.changed]!r}"
            f" pending={[c.key for c in self.pending]!r}>"
        )


def _capability_name(item: t.Any) -> str:
    if isinstance(item, Capability):
        return item.key
    return str(item)


class CapabilityPolicy:
    """A small allow-list policy usable as ``capability_policy``."""

    def __init__(
        self,
        allowed: t.Iterable[t.Any] = (),
        *,
        allow_all: bool | None = None,
        auto_approve: bool | None = None,
    ) -> None:
        if auto_approve is not None:
            allow_all = auto_approve
        self.allow_all = bool(allow_all)
        self.allowed = {_capability_name(item) for item in allowed}

    def allow(self, *items: t.Any) -> None:
        self.allowed.update(_capability_name(item) for item in items)

    def revoke(self, *items: t.Any) -> None:
        for item in items:
            self.allowed.discard(_capability_name(item))

    def review(self, review: CapabilityReview) -> bool:
        if self.allow_all:
            review.approve()
            return True

        for capability in review.pending:
            if capability.key in self.allowed or capability.name in self.allowed:
                review.approve(capability.key)

        review.approved = not review.pending
        return review.approved

    def __call__(self, review: CapabilityReview) -> bool:
        return self.review(review)
