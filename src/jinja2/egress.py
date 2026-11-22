"""Optional outbound (egress) protection for the sandboxed environment.

Regular sandboxing answers the question "what is a template allowed to *do*".
The protection mode in this module answers a different question: "what is the
rendered output allowed to *contain*".

A caller tags data values with a :class:`DisclosureLevel` when it builds the
render context.  An :class:`~jinja2.sandbox.SandboxedEnvironment` subclass is
then configured with an *egress license* -- the maximum level that may leave
the renderer.  Any value influenced by data above that level causes the whole
rendering to fail with :class:`EgressError`, both for :meth:`render` and for
streaming :meth:`~jinja2.Template.generate`.

The protection covers:

* plain field reads (``{{ ticket.secret }}``),
* concatenation and filters (``{{ a ~ b }}``, ``{{ x|upper }}``),
* conditional branches, including data that only influences *which* text is
  emitted without ever being printed itself,
* macro and call-block output.

Taint never silently disappears: combining a labeled value with anything else
keeps the more restrictive label, and unsupported template constructs can be
declared up front so that rendering fails safely instead of producing a
partially protected result.
"""

from __future__ import annotations

import enum
import typing as t
from contextvars import ContextVar

from . import nodes
from .compiler import CodeGenerator
from .environment import Template
from .exceptions import SecurityError
from .sandbox import SandboxedEnvironment

if t.TYPE_CHECKING:
    from .compiler import Frame
    from .runtime import Context


class EgressError(SecurityError):
    """Raised when a protected rendering would disclose data above the
    configured egress license.

    The error is raised only after the whole template has been evaluated, so
    that streaming callers never receive a prefix that could reveal the
    protected decision.
    """


class DisclosureLevel(enum.IntEnum):
    """Ordered disclosure levels.  A higher number is more restrictive."""

    #: Data that may be shown to anyone.
    PUBLIC = 10
    #: Data restricted to internal exports.
    INTERNAL = 20
    #: Data restricted to a small, explicitly authorized audience.
    RESTRICTED = 30


#: Sentinel meaning "no level has been assigned yet".  It behaves like the
#: least restrictive level when joined with a real level.
NO_LEVEL = -1


def join_levels(*levels: int) -> int:
    """Return the most restrictive (highest) level of the arguments."""
    return max(levels, default=NO_LEVEL)


def level_of(value: t.Any) -> int:
    """Return the disclosure level attached to a value, or :data:`NO_LEVEL`."""
    level = getattr(value, "__disclosure_level__", None)
    return NO_LEVEL if level is None else int(level)


def wrap(value: t.Any, level: int) -> t.Any:
    """Attach a disclosure level to a value without wrapping already labeled
    values twice.  The higher level wins.
    """
    if level is NO_LEVEL or level is None:
        return value

    current = level_of(value)

    if current >= level:
        return value

    if isinstance(value, Labeled):
        value.__disclosure_level__ = join_levels(current, level)
        return value

    return Labeled(value, join_levels(current, level))


def unwrap(value: t.Any) -> t.Any:
    """Return the underlying value if ``value`` is labeled, else the value."""
    if isinstance(value, Labeled):
        return value._value
    return value


class Labeled:
    """A transparent wrapper carrying a disclosure level.

    Every operation delegates to the wrapped object, and any value derived
    from a labeled value keeps (or raises) its level.  The wrapper is
    intentionally transparent: ``str(labeled)`` renders the wrapped value and
    comparisons, arithmetic, attribute and item access all behave like the
    underlying object while propagating taint.
    """

    __slots__ = ("_value", "__disclosure_level__")

    def __init__(self, value: t.Any, level: int) -> None:
        object.__setattr__(self, "_value", value)
        object.__setattr__(self, "__disclosure_level__", int(level))

    def __repr__(self) -> str:
        return f"Labeled({self._value!r}, level={self.__disclosure_level__})"

    def __str__(self) -> str:
        return str(self._value)

    def __bytes__(self) -> bytes:
        return bytes(self._value)

    def __format__(self, format_spec: str) -> str:
        return format(self._value, format_spec)

    def __bool__(self) -> bool:
        return bool(self._value)

    def __len__(self) -> int:
        return len(self._value)

    def __iter__(self) -> t.Iterator[t.Any]:
        level = self.__disclosure_level__
        return iter(wrap(item, level) for item in self._value)

    def __contains__(self, item: t.Any) -> bool:
        return item in self._value

    def __getattr__(self, name: str) -> t.Any:
        # Only called when normal lookup fails, so ``_value`` / the level slot
        # are not intercepted here.
        return wrap(getattr(self._value, name), self.__disclosure_level__)

    def __getitem__(self, key: t.Any) -> t.Any:
        return wrap(self._value[key], self.__disclosure_level__)

    def __call__(self, *args: t.Any, **kwargs: t.Any) -> t.Any:
        return wrap(self._value(*args, **kwargs), self.__disclosure_level__)

    def __eq__(self, other: t.Any) -> bool:
        return self._value == unwrap(other)

    def __ne__(self, other: t.Any) -> bool:
        return self._value != unwrap(other)

    def __lt__(self, other: t.Any) -> bool:
        return self._value < unwrap(other)

    def __le__(self, other: t.Any) -> bool:
        return self._value <= unwrap(other)

    def __gt__(self, other: t.Any) -> bool:
        return self._value > unwrap(other)

    def __ge__(self, other: t.Any) -> bool:
        return self._value >= unwrap(other)

    def __hash__(self) -> int:
        return hash(self._value)

    def _derive(self, result: t.Any) -> t.Any:
        return wrap(result, self.__disclosure_level__)

    def __add__(self, other: t.Any) -> t.Any:
        return self._derive(self._value + unwrap(other))

    def __radd__(self, other: t.Any) -> t.Any:
        return self._derive(other + self._value)

    def __sub__(self, other: t.Any) -> t.Any:
        return self._derive(self._value - unwrap(other))

    def __rsub__(self, other: t.Any) -> t.Any:
        return self._derive(other - self._value)

    def __mul__(self, other: t.Any) -> t.Any:
        return self._derive(self._value * unwrap(other))

    def __rmul__(self, other: t.Any) -> t.Any:
        return self._derive(other * self._value)

    def __truediv__(self, other: t.Any) -> t.Any:
        return self._derive(self._value / unwrap(other))

    def __rtruediv__(self, other: t.Any) -> t.Any:
        return self._derive(other / self._value)

    def __floordiv__(self, other: t.Any) -> t.Any:
        return self._derive(self._value // unwrap(other))

    def __rfloordiv__(self, other: t.Any) -> t.Any:
        return self._derive(other // self._value)

    def __mod__(self, other: t.Any) -> t.Any:
        return self._derive(self._value % unwrap(other))

    def __rmod__(self, other: t.Any) -> t.Any:
        return self._derive(other % self._value)

    def __pow__(self, other: t.Any) -> t.Any:
        return self._derive(self._value ** unwrap(other))

    def __neg__(self) -> t.Any:
        return self._derive(-self._value)

    def __pos__(self) -> t.Any:
        return self._derive(+self._value)


class GuardedStr(str):
    """A rendered output chunk carrying the highest disclosure level that
    influenced it (explicit data plus the active branch context).
    """

    __slots__ = ("__disclosure_level__",)

    def __new__(cls, text: str, level: int) -> GuardedStr:
        self = super().__new__(cls, text)
        self.__disclosure_level__ = int(level)
        return self


class _Tracker:
    """Per-render bookkeeping for the protection mode.

    A single tracker is active for a whole rendering, including nested macro
    calls and included templates.  ``pc`` is the stack of disclosure levels
    introduced by the conditional branches currently being evaluated (the
    *program counter* taint).
    """

    __slots__ = ("pc", "max_output_level", "license_level")

    def __init__(self, license_level: int) -> None:
        self.pc: list[int] = []
        self.max_output_level: int = NO_LEVEL
        self.license_level = license_level

    def branch_level(self) -> int:
        return join_levels(*self.pc) if self.pc else NO_LEVEL

    def enter_branch(self, value: t.Any) -> bool:
        level = join_levels(self.branch_level(), level_of(value))
        self.pc.append(level)
        return bool(value)

    def exit_branch(self) -> None:
        self.pc.pop()

    def guard_output(self, value: t.Any) -> t.Any:
        level = join_levels(level_of(value), self.branch_level())

        if level is NO_LEVEL:
            return value

        if level > self.max_output_level:
            self.max_output_level = level

        return GuardedStr("" if value is None else str(value), level)

    def check(self) -> None:
        level = self.max_output_level

        if level != NO_LEVEL and level > self.license_level:
            raise EgressError(
                f"rendering produced data at disclosure level {level} but the"
                f" egress license only permits level {self.license_level}."
            )


_current_tracker: ContextVar[_Tracker | None] = ContextVar(
    "jinja2_egress_tracker", default=None
)


def _tracker() -> _Tracker:
    tracker = _current_tracker.get()

    if tracker is None:
        raise RuntimeError(
            "egress guard helpers can only be used while a protected"
            " EgressSandboxedEnvironment is rendering."
        )

    return tracker


def enter_branch(value: t.Any) -> bool:
    """Push a branch frame and return the original truth value."""
    return _tracker().enter_branch(value)


def exit_branch() -> None:
    """Runtime helper emitted by the code generator at the end of a branch."""
    _tracker().exit_branch()


def guard_output(value: t.Any) -> t.Any:
    """Runtime helper emitted around every dynamic output expression."""
    return _tracker().guard_output(value)


def guard_concat(seq: t.Iterable[t.Any]) -> str:
    """Replacement for Jinja's ``str_join``/``markup_join`` in protected
    templates.

    The ``~`` concatenation operator and macro buffers are joined with this
    helper so that joining a public and a restricted value produces a
    restricted string instead of silently dropping the label.
    """
    parts = list(seq)
    level = join_levels(*(level_of(part) for part in parts))
    text = "".join("" if part is None else str(part) for part in parts)

    if level is NO_LEVEL:
        return text

    return GuardedStr(text, level)


class egress_guard:
    """Activate a tracker for the duration of one render.

    The same tracker is shared by nested macros, includes and blocks because
    they all render inside the same call stack.  Entering the guard twice
    (for example an included template rendered through ``Template.render``)
    creates an independent, nested scope so the inner render checks itself.
    """

    def __init__(self, license_level: int) -> None:
        self._tracker = _Tracker(license_level)
        self._token: t.Any = None

    def __enter__(self) -> _Tracker:
        self._token = _current_tracker.set(self._tracker)
        return self._tracker

    def __exit__(self, *exc: t.Any) -> None:
        _current_tracker.reset(self._token)

    def check(self) -> None:
        self._tracker.check()


class EgressCodeGenerator(CodeGenerator):
    """Code generator that instruments output, branches and joins.

    Every dynamic output expression is wrapped in :func:`guard_output`,
    conditional and loop bodies run inside a branch taint frame, and the
    ``~`` concatenation uses :func:`guarded_join` so that a single labeled
    operand labels the whole joined string.
    """

    def write_commons(self) -> None:
        super().write_commons()
        self.writeline(
            "from jinja2.egress import enter_branch, exit_branch,"
            " guard_output, guarded_join"
        )

    def _output_child_pre(
        self, node: nodes.Expr, frame: Frame, finalize: CodeGenerator._FinalizeInfo
    ) -> None:
        super()._output_child_pre(node, frame, finalize)
        self.write("guard_output(")

    def _output_child_post(
        self, node: nodes.Expr, frame: Frame, finalize: CodeGenerator._FinalizeInfo
    ) -> None:
        self.write(")")
        super()._output_child_post(node, frame, finalize)

    def visit_Concat(self, node: nodes.Concat, frame: Frame) -> None:
        self.write("guarded_join((")
        for arg in node.nodes:
            self.visit(arg, frame)
            self.write(", ")
        self.write("))")

    def _output_const_repr(self, group: t.Iterable[t.Any]) -> str:
        val = super()._output_const_repr(group)
        return f"guard_output({val})"

    def _branch_block(self, keyword, test, body, frame, node):
        self.writeline(keyword + (" " if keyword else ""), node)

        if test is not None:
            self.write("enter_branch(")
            self.visit(test, frame)
            self.write("):")
        else:
            self.write(":")

        self.indent()
        self.writeline("try:")
        self.indent()

        if test is None:
            self.writeline("enter_branch(None)")

        self.blockvisit(body, frame)
        self.outdent()
        self.writeline("finally:")
        self.indent()
        self.writeline("exit_branch()")
        self.outdent()
        self.outdent()

    def visit_If(self, node: nodes.If, frame: Frame) -> None:
        if_frame = frame.soft()
        self._branch_block("if", node.test, node.body, if_frame, node)

        for elif_ in node.elif_:
            self._branch_block("elif", elif_.test, elif_.body, if_frame, elif_)

        if node.else_:
            self._branch_block("else", None, node.else_, if_frame, node)


class EgressTemplate(Template):
    """Template enforcing the outbound disclosure license."""

    def _guarded_render(self, ctx: Context) -> t.Iterator[str]:
        guard = egress_guard(self.environment.egress_license)
        with guard:
            for chunk in self.root_render_func(ctx):  # noqa: UP028
                yield chunk
            guard.check()

    def render(self, *args: t.Any, **kwargs: t.Any) -> str:
        if self.environment.is_async:
            import asyncio

            return asyncio.run(self.render_async(*args, **kwargs))

        ctx = self.new_context(dict(*args, **kwargs))

        try:
            return self.environment.concat(self._guarded_render(ctx))
        except Exception:
            self.environment.handle_exception()

    def generate(self, *args: t.Any, **kwargs: t.Any) -> t.Iterator[str]:
        if self.environment.is_async:
            import asyncio

            async def to_list() -> list[str]:
                return [x async for x in self.generate_async(*args, **kwargs)]

            yield from asyncio.run(to_list())
            return

        ctx = self.new_context(dict(*args, **kwargs))
        buffered: list[str] = []

        try:
            with egress_guard(self.environment.egress_license) as guard:
                for chunk in self.root_render_func(ctx):
                    buffered.append(chunk)
                guard.check()
        except Exception:
            yield self.environment.handle_exception()
            return

        yield from buffered

    async def render_async(self, *args: t.Any, **kwargs: t.Any) -> str:
        if not self.environment.is_async:
            raise RuntimeError(
                "The environment was not created with async mode enabled."
            )

        ctx = self.new_context(dict(*args, **kwargs))

        try:
            with egress_guard(self.environment.egress_license) as guard:
                parts = [n async for n in self.root_render_func(ctx)]
                guard.check()
            return self.environment.concat(parts)
        except Exception:
            return self.environment.handle_exception()


class EgressSandboxedEnvironment(SandboxedEnvironment):
    """Sandboxed environment with optional outbound disclosure protection.

    :param egress_license: maximum :class:`DisclosureLevel` allowed to leave
        the renderer. Output containing more restrictive data raises
        :class:`EgressError` instead of being emitted.
    :param unsupported_constructs: AST statement/expression node classes that
        must be rejected at compile time, so an unsupported template fails
        safely before it can render.
    """

    code_generator_class = EgressCodeGenerator
    template_class: type[Template] = EgressTemplate

    def __init__(
        self,
        *args: t.Any,
        egress_license: int = DisclosureLevel.PUBLIC,
        unsupported_constructs: t.Collection[type[nodes.Node]] | None = None,
        **kwargs: t.Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.egress_license = int(egress_license)
        self.unsupported_constructs = frozenset(unsupported_constructs or ())
        self.intercepted_binops = frozenset(self.default_binop_table)
        self.intercepted_unops = frozenset(self.default_unop_table)
        self._wrap_filters()

    def _parse(self, source: str, name: str | None, filename: str | None):
        parsed = super()._parse(source, name, filename)
        self._validate_constructs(parsed)
        return parsed

    def _validate_constructs(self, template: nodes.Template) -> None:
        for forbidden in self.unsupported_constructs:
            found = template.find(forbidden)

            if found is not None:
                raise EgressError(
                    f"construct {forbidden.__name__} is not supported by this "
                    "egress policy."
                )

    def call_binop(self, context: Context, op: str, left: t.Any, right: t.Any) -> t.Any:
        result = super().call_binop(context, op, left, right)
        level = join_levels(level_of(left), level_of(right))
        return result if level is NO_LEVEL else wrap(result, level)

    def call_unop(self, context: Context, op: str, arg: t.Any) -> t.Any:
        result = super().call_unop(context, op, arg)
        level = level_of(arg)
        return result if level is NO_LEVEL else wrap(result, level)

    def call(
        __self, __context: Context, __obj: t.Any, *args: t.Any, **kwargs: t.Any
    ) -> t.Any:
        result = super().call(__context, __obj, *args, **kwargs)
        level = join_levels(
            level_of(__obj),
            *[level_of(a) for a in args],
            *[level_of(v) for v in kwargs.values()],
        )
        return result if level is NO_LEVEL else wrap(result, level)

    def getitem(self, obj: t.Any, argument: t.Any) -> t.Any:
        result = super().getitem(obj, argument)
        level = join_levels(level_of(obj), level_of(argument))
        return result if level is NO_LEVEL else wrap(result, level)

    def getattr(self, obj: t.Any, attribute: str) -> t.Any:
        result = super().getattr(obj, attribute)
        level = level_of(obj)
        return result if level is NO_LEVEL else wrap(result, level)

    def protect_fields(
        self, data: t.Mapping[str, t.Any], field_levels: t.Mapping[str, int]
    ) -> dict[str, t.Any]:
        """Return ``data`` with the named fields wrapped at their level."""
        protected = dict(data)

        for name, level in field_levels.items():
            if name in protected:
                protected[name] = wrap(protected[name], int(level))

        return protected

    def _wrap_filters(self) -> None:
        for name, func in list(self.filters.items()):
            self.filters[name] = self._taint_filter(func)

    @staticmethod
    def _taint_filter(func: t.Callable[..., t.Any]) -> t.Callable[..., t.Any]:
        def wrapper(value: t.Any, *args: t.Any, **kwargs: t.Any) -> t.Any:
            level = join_levels(
                level_of(value),
                *[level_of(a) for a in args],
                *[level_of(v) for v in kwargs.values()],
            )
            result = func(value, *args, **kwargs)
            return result if level is NO_LEVEL else wrap(result, level)

        wrapper.__name__ = getattr(func, "__name__", "wrapped_filter")
        return wrapper


#: Alias used by the generated code for the protected ``~`` join.

guarded_join = guard_concat
