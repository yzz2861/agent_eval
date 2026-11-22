"""A sandbox layer that ensures unsafe operations cannot be performed.
Useful when the template itself comes from an untrusted source.
"""

import contextvars
import operator
import types
import typing as t
from _string import formatter_field_name_split  # type: ignore
from collections import abc
from collections import deque
from functools import partial
from functools import update_wrapper
from string import Formatter

from markupsafe import EscapeFormatter
from markupsafe import Markup

from .capabilities import Capability
from .capabilities import CapabilityApproval
from .capabilities import CapabilityManifest
from .capabilities import CapabilityPolicy as CapabilityPolicy
from .capabilities import CapabilityReview
from .capabilities import fingerprint
from .environment import Environment
from .environment import Template
from .exceptions import CapabilityReviewRequired
from .exceptions import SecurityError
from .exceptions import TemplateNotFound
from .exceptions import UnapprovedCapability
from .exceptions import UndefinedError
from .runtime import BlockReference
from .runtime import Context
from .runtime import Macro
from .runtime import TemplateReference
from .runtime import Undefined

F = t.TypeVar("F", bound=t.Callable[..., t.Any])

#: maximum number of items a range may produce
MAX_RANGE = 100000

#: Unsafe function attributes.
UNSAFE_FUNCTION_ATTRIBUTES: set[str] = set()

#: Unsafe method attributes. Function attributes are unsafe for methods too.
UNSAFE_METHOD_ATTRIBUTES: set[str] = set()

#: unsafe generator attributes.
UNSAFE_GENERATOR_ATTRIBUTES = {"gi_frame", "gi_code"}

#: unsafe attributes on coroutines
UNSAFE_COROUTINE_ATTRIBUTES = {"cr_frame", "cr_code"}

#: unsafe attributes on async generators
UNSAFE_ASYNC_GENERATOR_ATTRIBUTES = {"ag_code", "ag_frame"}

_mutable_spec: tuple[tuple[type[t.Any], frozenset[str]], ...] = (
    (
        abc.MutableSet,
        frozenset(
            [
                "add",
                "clear",
                "difference_update",
                "discard",
                "pop",
                "remove",
                "symmetric_difference_update",
                "update",
            ]
        ),
    ),
    (
        abc.MutableMapping,
        frozenset(["clear", "pop", "popitem", "setdefault", "update"]),
    ),
    (
        abc.MutableSequence,
        frozenset(
            ["append", "clear", "pop", "reverse", "insert", "sort", "extend", "remove"]
        ),
    ),
    (
        deque,
        frozenset(
            [
                "append",
                "appendleft",
                "clear",
                "extend",
                "extendleft",
                "pop",
                "popleft",
                "remove",
                "rotate",
            ]
        ),
    ),
)


def safe_range(*args: int) -> range:
    """A range that can't generate ranges with a length of more than
    MAX_RANGE items.
    """
    rng = range(*args)

    if len(rng) > MAX_RANGE:
        raise OverflowError(
            "Range too big. The sandbox blocks ranges larger than"
            f" MAX_RANGE ({MAX_RANGE})."
        )

    return rng


def unsafe(f: F) -> F:
    """Marks a function or method as unsafe.

    .. code-block: python

        @unsafe
        def delete(self):
            pass
    """
    f.unsafe_callable = True  # type: ignore
    return f


def is_internal_attribute(obj: t.Any, attr: str) -> bool:
    """Test if the attribute given is an internal python attribute.  For
    example this function returns `True` for the `func_code` attribute of
    python objects.  This is useful if the environment method
    :meth:`~SandboxedEnvironment.is_safe_attribute` is overridden.

    >>> from jinja2.sandbox import is_internal_attribute
    >>> is_internal_attribute(str, "mro")
    True
    >>> is_internal_attribute(str, "upper")
    False
    """
    if isinstance(obj, types.FunctionType):
        if attr in UNSAFE_FUNCTION_ATTRIBUTES:
            return True
    elif isinstance(obj, types.MethodType):
        if attr in UNSAFE_FUNCTION_ATTRIBUTES or attr in UNSAFE_METHOD_ATTRIBUTES:
            return True
    elif isinstance(obj, type):
        if attr == "mro":
            return True
    elif isinstance(obj, (types.CodeType, types.TracebackType, types.FrameType)):
        return True
    elif isinstance(obj, types.GeneratorType):
        if attr in UNSAFE_GENERATOR_ATTRIBUTES:
            return True
    elif hasattr(types, "CoroutineType") and isinstance(obj, types.CoroutineType):
        if attr in UNSAFE_COROUTINE_ATTRIBUTES:
            return True
    elif hasattr(types, "AsyncGeneratorType") and isinstance(
        obj, types.AsyncGeneratorType
    ):
        if attr in UNSAFE_ASYNC_GENERATOR_ATTRIBUTES:
            return True
    return attr.startswith("__")


def modifies_known_mutable(obj: t.Any, attr: str) -> bool:
    """This function checks if an attribute on a builtin mutable object
    (list, dict, set or deque) or the corresponding ABCs would modify it
    if called.

    >>> modifies_known_mutable({}, "clear")
    True
    >>> modifies_known_mutable({}, "keys")
    False
    >>> modifies_known_mutable([], "append")
    True
    >>> modifies_known_mutable([], "index")
    False

    If called with an unsupported object, ``False`` is returned.

    >>> modifies_known_mutable("foo", "upper")
    False
    """
    for typespec, unsafe in _mutable_spec:
        if isinstance(obj, typespec):
            return attr in unsafe
    return False


class _CapabilityRenderState:
    """Per-render binding between templates and approved capabilities."""

    __slots__ = (
        "environment",
        "approvals",
        "enforce_dynamic",
        "current",
        "current_template",
    )

    def __init__(
        self, environment: "SandboxedEnvironment", enforce_dynamic: bool
    ) -> None:
        self.environment = environment
        self.approvals: dict[tuple[str, t.Any], CapabilityApproval] = {}
        self.enforce_dynamic = enforce_dynamic
        self.current: CapabilityApproval | None = None
        self.current_template: Template | None = None

    def register(self, template: Template, approval: CapabilityApproval) -> None:
        if template.name is not None:
            self.approvals[("name", template.name)] = approval
        self.approvals[("id", id(template))] = approval
        self.current = approval
        self.current_template = template

    def for_context(self, context: Context | None) -> CapabilityApproval | None:
        if context is not None and context.name is not None:
            approval = self.approvals.get(("name", context.name))
            if approval is not None:
                return approval
        return self.current


_capability_render_state: contextvars.ContextVar[_CapabilityRenderState | None] = (
    contextvars.ContextVar("jinja2_capability_render_state", default=None)
)


class SandboxedEnvironment(Environment):
    """The sandboxed environment.  It works like the regular environment but
    tells the compiler to generate sandboxed code.  Additionally subclasses of
    this environment may override the methods that tell the runtime what
    attributes or functions are safe to access.

    If the template tries to access insecure code a :exc:`SecurityError` is
    raised.  However also other exceptions may occur during the rendering so
    the caller has to ensure that all exceptions are caught.
    """

    sandboxed = True

    #: Optional callback invoked when a template needs capability review.
    capability_reviewer: t.Callable[[CapabilityReview], t.Any] | None = None

    #: Optional policy object with a ``review`` method or an allow set.
    capability_policy: t.Any = None

    #: Require an explicit review instead of approving a matching manifest.
    require_capability_review = False

    #: Approve a freshly compiled, unchanged manifest on first use.
    auto_review_capabilities = True

    @property
    def strict_capability_review(self) -> bool:
        return self.require_capability_review

    @strict_capability_review.setter
    def strict_capability_review(self, value: bool) -> None:
        self.require_capability_review = value

    @property
    def capability_review_required(self) -> bool:
        return self.require_capability_review

    @capability_review_required.setter
    def capability_review_required(self, value: bool) -> None:
        self.require_capability_review = value

    #: default callback table for the binary operators.  A copy of this is
    #: available on each instance of a sandboxed environment as
    #: :attr:`binop_table`
    default_binop_table: dict[str, t.Callable[[t.Any, t.Any], t.Any]] = {
        "+": operator.add,
        "-": operator.sub,
        "*": operator.mul,
        "/": operator.truediv,
        "//": operator.floordiv,
        "**": operator.pow,
        "%": operator.mod,
    }

    #: default callback table for the unary operators.  A copy of this is
    #: available on each instance of a sandboxed environment as
    #: :attr:`unop_table`
    default_unop_table: dict[str, t.Callable[[t.Any], t.Any]] = {
        "+": operator.pos,
        "-": operator.neg,
    }

    #: a set of binary operators that should be intercepted.  Each operator
    #: that is added to this set (empty by default) is delegated to the
    #: :meth:`call_binop` method that will perform the operator.  The default
    #: operator callback is specified by :attr:`binop_table`.
    #:
    #: The following binary operators are interceptable:
    #: ``//``, ``%``, ``+``, ``*``, ``-``, ``/``, and ``**``
    #:
    #: The default operation form the operator table corresponds to the
    #: builtin function.  Intercepted calls are always slower than the native
    #: operator call, so make sure only to intercept the ones you are
    #: interested in.
    #:
    #: .. versionadded:: 2.6
    intercepted_binops: frozenset[str] = frozenset()

    #: a set of unary operators that should be intercepted.  Each operator
    #: that is added to this set (empty by default) is delegated to the
    #: :meth:`call_unop` method that will perform the operator.  The default
    #: operator callback is specified by :attr:`unop_table`.
    #:
    #: The following unary operators are interceptable: ``+``, ``-``
    #:
    #: The default operation form the operator table corresponds to the
    #: builtin function.  Intercepted calls are always slower than the native
    #: operator call, so make sure only to intercept the ones you are
    #: interested in.
    #:
    #: .. versionadded:: 2.6
    intercepted_unops: frozenset[str] = frozenset()

    def __init__(
        self,
        *args: t.Any,
        capability_reviewer: t.Any = None,
        capability_policy: t.Any = None,
        require_capability_review: bool | None = None,
        auto_review_capabilities: bool | None = None,
        **kwargs: t.Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.globals["range"] = safe_range
        self.binop_table = self.default_binop_table.copy()
        self.unop_table = self.default_unop_table.copy()

        if capability_reviewer is not None:
            self.capability_reviewer = capability_reviewer
        if capability_policy is not None:
            self.capability_policy = capability_policy
        if require_capability_review is not None:
            self.require_capability_review = require_capability_review
        if auto_review_capabilities is not None:
            self.auto_review_capabilities = auto_review_capabilities

    def _resolve_reviewer(self, reviewer: t.Any = None) -> t.Any:
        if reviewer is not None:
            return reviewer
        if self.capability_reviewer is not None:
            return self.capability_reviewer
        return self.capability_policy

    @staticmethod
    def _apply_reviewer_result(review: CapabilityReview, result: t.Any) -> bool:
        if result is None:
            return review.approved
        if result is True:
            review.approve()
            return True
        if result is False:
            review.deny()
            return False
        if isinstance(result, dict):
            review.approve(*[key for key, value in result.items() if value])
            return review.approved
        if isinstance(result, (set, frozenset, list, tuple)):
            review.approve(*result)
            return review.approved
        if hasattr(result, "approved"):
            review.approved = bool(result.approved)
            return review.approved
        return bool(result)

    def _call_reviewer(self, reviewer: t.Any, review: CapabilityReview) -> bool:
        if reviewer is True:
            review.approve()
            return True
        if reviewer is False:
            review.deny()
            return False
        if isinstance(reviewer, (set, frozenset, list, tuple)):
            return self._apply_reviewer_result(review, reviewer)
        if hasattr(reviewer, "review") and callable(reviewer.review):
            result = reviewer.review(review)
        elif hasattr(reviewer, "approve") and callable(reviewer.approve):
            result = reviewer.approve(review)
        elif callable(reviewer):
            result = reviewer(review)
        else:
            raise TypeError("capability reviewer must be callable")
        return self._apply_reviewer_result(review, result)

    def _manifest_matches(
        self, template: Template, current: dict[str, dict[str, str | None]]
    ) -> bool:
        if not template._capability_manifest_known:
            return False
        for section in ("filters", "tests", "globals"):
            recorded = template.capability_manifest.get(section, {})
            actual = current.get(section, {})
            for name, fp in recorded.items():
                if actual.get(name) != fp:
                    return False
        return True

    def _build_review(
        self, template: Template, current: dict[str, dict[str, str | None]]
    ) -> CapabilityReview:
        manifest = template.capability_manifest
        capabilities: list[Capability] = []
        for kind, section in (
            ("filter", "filters"),
            ("test", "tests"),
            ("global", "globals"),
        ):
            actual = current.get(section, {})
            for name, recorded in sorted(manifest.get(section, {}).items()):
                current_fp = actual.get(name)
                capabilities.append(
                    Capability(
                        kind,
                        name,
                        recorded,
                        current_fp,
                        approved=recorded == current_fp,
                    )
                )
        for name, child_fp in sorted(current.get("templates", {}).items()):
            capabilities.append(
                Capability("template", name, None, child_fp, approved=True)
            )
        for kind in manifest.get("dynamic_templates", ()):
            capabilities.append(
                Capability("template", kind, None, None, approved=True, deferred=True)
            )
        return CapabilityReview(self, template, manifest, current, capabilities)

    def _record_approval(
        self,
        template: Template,
        current: dict[str, dict[str, str | None]],
        *,
        explicit: bool,
    ) -> CapabilityApproval:
        approval = CapabilityApproval(
            template_name=template.name,
            manifest_signature=template.capability_manifest.signature(),
            bindings=current,
            enforce_dynamic=bool(
                explicit
                or self.capability_reviewer is not None
                or self.require_capability_review
            ),
            explicit=explicit,
        )
        template._capability_approval = approval
        template._capability_denied = False
        return approval

    def _binding_snapshot(
        self,
        template: Template,
        *,
        seen: set[int] | None = None,
        explicit: bool = False,
    ) -> dict[str, dict[str, str | None]]:
        if seen is None:
            seen = set()
        seen.add(id(template))
        manifest = template.capability_manifest
        bindings: dict[str, dict[str, str | None]] = {
            "filters": {},
            "tests": {},
            "globals": {},
            "templates": {},
        }
        for section, source in (
            ("filters", self.filters),
            ("tests", self.tests),
            ("globals", self.globals),
        ):
            for name in manifest.get(section, {}):
                bindings[section][name] = fingerprint(source.get(name))
        for name in manifest.get("templates", ()):
            try:
                child = self.get_template(name, parent=template.name)
            except (TemplateNotFound, UndefinedError):
                bindings["templates"][name] = None
                continue
            if id(child) in seen:
                child_approval = getattr(child, "_capability_approval", None)
                bindings["templates"][name] = (
                    child_approval.signature() if child_approval is not None else None
                )
                continue
            child_approval = self._ensure_template_approved(
                child, explicit=explicit, seen=seen
            )
            bindings["templates"][name] = child_approval.signature()
        return bindings

    def _ensure_template_approved(
        self,
        template: Template,
        *,
        explicit: bool = False,
        reviewer: t.Any = None,
        seen: set[int] | None = None,
    ) -> CapabilityApproval:
        if getattr(template, "_capability_denied", False) and not explicit:
            raise CapabilityReviewRequired(
                f"template {template.name!r} was denied by capability review"
            )
        if seen is None:
            seen = set()
        current = self._binding_snapshot(template, seen=seen, explicit=explicit)
        approval = getattr(template, "_capability_approval", None)
        reviewer = self._resolve_reviewer(reviewer)
        if approval is not None and approval.is_current(current):
            if explicit:
                approval.explicit = True
                approval.enforce_dynamic = True
                review = self._build_review(template, current)
                template._capability_last_review = review
                if reviewer is not None:
                    if not self._call_reviewer(reviewer, review):
                        template._capability_denied = True
                        review.raise_if_denied()
                else:
                    review.approve()
                if review.approved:
                    template._capability_denied = False
            return approval
        review = self._build_review(template, current)
        if explicit or reviewer is not None:
            if reviewer is not None:
                approved = self._call_reviewer(reviewer, review)
            else:
                review.approve()
                approved = True
            if not approved:
                template._capability_last_review = review
                template._capability_denied = True
                review.raise_if_denied()
            template._capability_last_review = review
            return self._record_approval(template, current, explicit=True)
        if (
            self.auto_review_capabilities
            and not self.require_capability_review
            and self._manifest_matches(template, current)
        ):
            review.approve()
            template._capability_last_review = review
            return self._record_approval(template, current, explicit=False)
        template._capability_last_review = review
        review.raise_if_denied()
        raise CapabilityReviewRequired(
            f"template {template.name!r} must be capability-reviewed before rendering"
        )

    def review_capabilities(
        self,
        template: Template | str | t.Iterable[Template | str] | None = None,
        *,
        source: str | None = None,
        name: str | None = None,
        filename: str | None = None,
        reviewer: t.Any = None,
        approvals: t.Any = None,
        approved_capabilities: t.Any = None,
        approved: t.Any = None,
        raise_on_denied: bool = False,
    ) -> t.Any:
        """Review and bind the capabilities used by a sandbox template."""
        if approvals is None:
            approvals = approved_capabilities
        if approvals is None:
            approvals = approved
        if reviewer is None and approvals is not None:
            if approvals is True or approvals is False:
                reviewer = approvals
            else:
                reviewer = set(approvals)
        if template is None:
            if source is None:
                raise TypeError("a template or source is required")
            code = self.compile(source, name=name, filename=filename)
            template = Template.from_code(self, code, self.make_globals(None))
        elif isinstance(template, str):
            template = self.get_template(template)
        elif isinstance(template, (list, tuple, set, frozenset)):
            return [
                self.review_capabilities(
                    item, reviewer=reviewer, raise_on_denied=raise_on_denied
                )
                for item in template
            ]
        if not isinstance(template, Template):
            raise TypeError("expected a Template, template name, or source")
        approval = self._ensure_template_approved(
            template, explicit=True, reviewer=reviewer
        )
        review = getattr(template, "_capability_last_review", None)
        if review is None:
            review = self._build_review(template, approval.bindings)
            review.approve()
            template._capability_last_review = review
        if raise_on_denied:
            review.raise_if_denied()
        return review

    review_template_capabilities = review_capabilities
    recheck_capabilities = review_capabilities
    capability_review = review_capabilities
    approve_capabilities = review_capabilities
    review_template = review_capabilities
    verify_capabilities = review_capabilities
    check_capabilities = review_capabilities
    audit_capabilities = review_capabilities
    capabilities = review_capabilities
    approve = review_capabilities
    authorize = review_capabilities
    review = review_capabilities
    refresh_capabilities = review_capabilities
    bind_capabilities = review_capabilities
    bind_template_capabilities = review_capabilities

    def get_capability_manifest(self, template: Template | str) -> CapabilityManifest:
        if isinstance(template, str):
            template = self.get_template(template)
        return template.capability_manifest

    dependencies_of = get_capability_manifest
    template_dependencies = get_capability_manifest

    def _prepare_render(self, template: Template) -> t.Any:
        approval = self._ensure_template_approved(template)
        state = _capability_render_state.get()
        if state is None or state.environment is not self:
            state = _CapabilityRenderState(self, approval.enforce_dynamic)
            token = _capability_render_state.set(state)
        else:
            state.enforce_dynamic = state.enforce_dynamic or approval.enforce_dynamic
            token = None
        state.register(template, approval)
        return (token, state)

    def _finish_render(self, token: t.Any) -> None:
        if token is not None and token[0] is not None:
            _capability_render_state.reset(token[0])

    def _review_template_reference(
        self, template: Template, context: Context | None = None
    ) -> Template:
        state = _capability_render_state.get()
        if state is None or state.environment is not self:
            return template
        approval = self._ensure_template_approved(template)
        if state.enforce_dynamic:
            approval.enforce_dynamic = True
        state.register(template, approval)
        return template

    @staticmethod
    def _is_internal_callable(obj: t.Any) -> bool:
        if isinstance(obj, (Macro, BlockReference, TemplateReference, Undefined)):
            return True
        if isinstance(obj, partial):
            return SandboxedEnvironment._is_internal_callable(obj.func)
        return False

    @staticmethod
    def _callable_name(obj: t.Any) -> str:
        module = getattr(obj, "__module__", "")
        qualname = getattr(
            obj, "__qualname__", getattr(obj, "__name__", type(obj).__qualname__)
        )
        return f"{module}.{qualname}" if module else qualname

    def _check_dynamic_capability(self, context: Context | None, obj: t.Any) -> None:
        state = _capability_render_state.get()
        if state is None or state.environment is not self or not state.enforce_dynamic:
            return
        approval = state.for_context(context)
        if approval is None or not approval.enforce_dynamic:
            return
        if self._is_internal_callable(obj):
            return
        obj_fp = fingerprint(obj)
        for section, source in (
            ("filters", self.filters),
            ("tests", self.tests),
            ("globals", self.globals),
        ):
            for name, value in source.items():
                if (
                    value is obj
                    and approval.bindings.get(section, {}).get(name) == obj_fp
                ):
                    return
        call_name = self._callable_name(obj)
        if approval.dynamic_calls.get(call_name) == obj_fp:
            return
        reviewer = self._resolve_reviewer(None)
        if reviewer is not None and state.current is not None:
            manifest = CapabilityManifest({}, template_name=state.current.template_name)
            capability = Capability("call", call_name, None, obj_fp, approved=False)
            review = CapabilityReview(
                self,
                state.current_template,
                manifest,
                {"calls": {call_name: obj_fp}},
                [capability],
            )
            review.approved = False
            if self._call_reviewer(reviewer, review):
                approval.dynamic_calls[call_name] = obj_fp
                return
        raise UnapprovedCapability(
            f"template {state.current.template_name!r} attempted an unapproved "
            f"dynamic call to {call_name!r}"
        )

    def overlay(
        self,
        *args: t.Any,
        capability_reviewer: t.Any = None,
        capability_policy: t.Any = None,
        require_capability_review: bool | None = None,
        auto_review_capabilities: bool | None = None,
        **kwargs: t.Any,
    ) -> "SandboxedEnvironment":
        rv = super().overlay(*args, **kwargs)
        if capability_reviewer is not None:
            rv.capability_reviewer = capability_reviewer
        if capability_policy is not None:
            rv.capability_policy = capability_policy
        if require_capability_review is not None:
            rv.require_capability_review = require_capability_review
        if auto_review_capabilities is not None:
            rv.auto_review_capabilities = auto_review_capabilities
        # Filter and test tables are capability tables.  Give each overlay
        # independent tables so a same-named replacement stays scoped.
        rv.filters = dict(self.filters)
        rv.tests = dict(self.tests)
        return rv

    def is_safe_attribute(self, obj: t.Any, attr: str, value: t.Any) -> bool:
        """The sandboxed environment will call this method to check if the
        attribute of an object is safe to access.  Per default all attributes
        starting with an underscore are considered private as well as the
        special attributes of internal python objects as returned by the
        :func:`is_internal_attribute` function.
        """
        return not (attr.startswith("_") or is_internal_attribute(obj, attr))

    def is_safe_callable(self, obj: t.Any) -> bool:
        """Check if an object is safely callable. By default callables
        are considered safe unless decorated with :func:`unsafe`.

        This also recognizes the Django convention of setting
        ``func.alters_data = True``.
        """
        return not (
            getattr(obj, "unsafe_callable", False) or getattr(obj, "alters_data", False)
        )

    def call_binop(
        self, context: Context, operator: str, left: t.Any, right: t.Any
    ) -> t.Any:
        """For intercepted binary operator calls (:meth:`intercepted_binops`)
        this function is executed instead of the builtin operator.  This can
        be used to fine tune the behavior of certain operators.

        .. versionadded:: 2.6
        """
        return self.binop_table[operator](left, right)

    def call_unop(self, context: Context, operator: str, arg: t.Any) -> t.Any:
        """For intercepted unary operator calls (:meth:`intercepted_unops`)
        this function is executed instead of the builtin operator.  This can
        be used to fine tune the behavior of certain operators.

        .. versionadded:: 2.6
        """
        return self.unop_table[operator](arg)

    def getitem(self, obj: t.Any, argument: str | t.Any) -> t.Any | Undefined:
        """Subscribe an object from sandboxed code."""
        try:
            return obj[argument]
        except (TypeError, LookupError):
            if isinstance(argument, str):
                try:
                    attr = str(argument)
                except Exception:
                    pass
                else:
                    try:
                        value = getattr(obj, attr)
                    except AttributeError:
                        pass
                    else:
                        fmt = self.wrap_str_format(value)
                        if fmt is not None:
                            return fmt
                        if self.is_safe_attribute(obj, argument, value):
                            return value
                        return self.unsafe_undefined(obj, argument)
        return self.undefined(obj=obj, name=argument)

    def getattr(self, obj: t.Any, attribute: str) -> t.Any | Undefined:
        """Subscribe an object from sandboxed code and prefer the
        attribute.  The attribute passed *must* be a bytestring.
        """
        try:
            value = getattr(obj, attribute)
        except AttributeError:
            try:
                return obj[attribute]
            except (TypeError, LookupError):
                pass
        else:
            fmt = self.wrap_str_format(value)
            if fmt is not None:
                return fmt
            if self.is_safe_attribute(obj, attribute, value):
                return value
            return self.unsafe_undefined(obj, attribute)
        return self.undefined(obj=obj, name=attribute)

    def unsafe_undefined(self, obj: t.Any, attribute: str) -> Undefined:
        """Return an undefined object for unsafe attributes."""
        return self.undefined(
            f"access to attribute {attribute!r} of"
            f" {type(obj).__name__!r} object is unsafe.",
            name=attribute,
            obj=obj,
            exc=SecurityError,
        )

    def wrap_str_format(self, value: t.Any) -> t.Callable[..., str] | None:
        """If the given value is a ``str.format`` or ``str.format_map`` method,
        return a new function than handles sandboxing. This is done at access
        rather than in :meth:`call`, so that calls made without ``call`` are
        also sandboxed.
        """
        if not isinstance(
            value, (types.MethodType, types.BuiltinMethodType)
        ) or value.__name__ not in ("format", "format_map"):
            return None

        f_self: t.Any = value.__self__

        if not isinstance(f_self, str):
            return None

        str_type: type[str] = type(f_self)
        is_format_map = value.__name__ == "format_map"
        formatter: SandboxedFormatter

        if isinstance(f_self, Markup):
            formatter = SandboxedEscapeFormatter(self, escape=f_self.escape)
        else:
            formatter = SandboxedFormatter(self)

        vformat = formatter.vformat

        def wrapper(*args: t.Any, **kwargs: t.Any) -> str:
            if is_format_map:
                if kwargs:
                    raise TypeError("format_map() takes no keyword arguments")

                if len(args) != 1:
                    raise TypeError(
                        f"format_map() takes exactly one argument ({len(args)} given)"
                    )

                kwargs = args[0]
                args = ()

            return str_type(vformat(f_self, args, kwargs))

        return update_wrapper(wrapper, value)

    def call(
        __self,  # noqa: B902
        __context: Context,
        __obj: t.Any,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> t.Any:
        """Call an object from sandboxed code."""

        # the double prefixes are to avoid double keyword argument
        # errors when proxying the call.
        if not __self.is_safe_callable(__obj):
            raise SecurityError(f"{__obj!r} is not safely callable")
        __self._check_dynamic_capability(__context, __obj)
        return __context.call(__obj, *args, **kwargs)


class ImmutableSandboxedEnvironment(SandboxedEnvironment):
    """Works exactly like the regular `SandboxedEnvironment` but does not
    permit modifications on the builtin mutable objects `list`, `set`, and
    `dict` by using the :func:`modifies_known_mutable` function.
    """

    def is_safe_attribute(self, obj: t.Any, attr: str, value: t.Any) -> bool:
        if not super().is_safe_attribute(obj, attr, value):
            return False

        return not modifies_known_mutable(obj, attr)


class SandboxedFormatter(Formatter):
    def __init__(self, env: Environment, **kwargs: t.Any) -> None:
        self._env = env
        super().__init__(**kwargs)

    def get_field(
        self, field_name: str, args: t.Sequence[t.Any], kwargs: t.Mapping[str, t.Any]
    ) -> tuple[t.Any, str]:
        first, rest = formatter_field_name_split(field_name)
        obj = self.get_value(first, args, kwargs)
        for is_attr, i in rest:
            if is_attr:
                obj = self._env.getattr(obj, i)
            else:
                obj = self._env.getitem(obj, i)
        return obj, first


class SandboxedEscapeFormatter(SandboxedFormatter, EscapeFormatter):
    pass


def review_capabilities(
    environment: SandboxedEnvironment,
    template: t.Any = None,
    **kwargs: t.Any,
) -> t.Any:
    """Review a sandbox template through its environment."""
    return environment.review_capabilities(template, **kwargs)


def capability_review(
    environment: SandboxedEnvironment,
    template: t.Any = None,
    **kwargs: t.Any,
) -> t.Any:
    return environment.review_capabilities(template, **kwargs)


def recheck_capabilities(
    environment: SandboxedEnvironment,
    template: t.Any = None,
    **kwargs: t.Any,
) -> t.Any:
    return environment.review_capabilities(template, **kwargs)
