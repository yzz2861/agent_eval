"""Call-local conversion context support."""

from contextvars import ContextVar
from inspect import Parameter
from inspect import signature as inspect_signature
from typing import Any, Callable

from .types import Context

__all__ = ["MISSING_CONTEXT", "expects_context"]


class _MissingContext:
    pass


MISSING_CONTEXT = _MissingContext()

_current_context: ContextVar[Context | _MissingContext] = ContextVar(
    "cattrs_conversion_context", default=MISSING_CONTEXT
)


def expects_context(hook: Callable[..., Any]) -> bool:
    """Whether *hook* explicitly declares a ``context`` parameter."""
    try:
        sig = inspect_signature(hook)
    except (TypeError, ValueError):
        return False

    context_parameter = sig.parameters.get("context")
    return (
        context_parameter is not None
        and context_parameter.kind is Parameter.KEYWORD_ONLY
    )


def bind_context(hook: Callable[..., Any], *args: Any) -> Any:
    """Call a context-aware hook, adding the current context when present."""
    context = _current_context.get()
    if context is MISSING_CONTEXT:
        return hook(*args)
    return hook(*args, context=context)
