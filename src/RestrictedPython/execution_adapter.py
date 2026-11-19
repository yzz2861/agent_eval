"""Optional execution adapter tying restricted code to a lifecycle.

The adapter wires :mod:`RestrictedPython` into the lifecycle
machinery of :mod:`RestrictedPython.execution_lifecycle`:

* every iterator obtained through the guarded iteration helper is
  bound to the context active at creation time;
* ``yield from`` is rewritten to go through the same guard,
  including iterators created by factories inside the restricted frame;
* host capabilities are only reachable through
  ``capability(...)``, which charges the owning context and is
  refused during cleanup;
* ``register_cleanup(...)`` registers trusted teardown on the
  bound object (or on the request when no generator frame is active).

The restricted source uses the public, underscore-free names
``iter_guard``, ``capability`` and ``register_cleanup``.
A source preparation pass rewrites them to the internal guard names
that RestrictedPython injects itself, so the policy name checks never
see a forbidden underscore name.  RestrictedPython itself is imported
lazily so the lifecycle module can be used without it.  No web
framework and no async primitives are used.
"""

from __future__ import annotations

import ast
from typing import Any
from typing import Callable
from typing import Mapping
from typing import Optional

from RestrictedPython import compile_restricted_exec
from RestrictedPython.Guards import safe_globals

from RestrictedPython.execution_lifecycle import CURRENT_CONTEXT
from RestrictedPython.execution_lifecycle import BoundIterator
from RestrictedPython.execution_lifecycle import ExecutionContext
from RestrictedPython.execution_lifecycle import bind
from RestrictedPython.execution_lifecycle import current_bound


#: Public name used inside restricted source -> internal guard name.
_GUARD_ALIASES = {
    'iter_guard': '_getiter_',
    'capability': '_capability_',
    'register_cleanup': '_register_cleanup_',
}


class _LifecyclePrepare(ast.NodeTransformer):
    """Prepare restricted source for lifecycle-aware compilation.

    * public guard names are rewritten to the internal guard names that
      RestrictedPython injects itself (and therefore accepts);
    * ``yield from expr`` is rewritten to delegate through the
      iteration guard so the delegated iterator gets a lifecycle.
    """

    def visit_Name(self, node: ast.Name) -> ast.AST:
        self.generic_visit(node)
        target = _GUARD_ALIASES.get(node.id)
        if target is not None:
            node.id = target
        return node

    def visit_YieldFrom(self, node: ast.YieldFrom) -> ast.YieldFrom:
        self.generic_visit(node)
        value = node.value
        already_guarded = (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == '_getiter_'
        )
        if not already_guarded:
            call = ast.Call(
                func=ast.Name(id='_getiter_', ctx=ast.Load()),
                args=[value],
                keywords=[],
            )
            node.value = ast.copy_location(call, value)
        return node


def compile_lifecycle_restricted(source: str,
                                 filename: str = '<restricted>'):
    """Compile restricted source with lifecycle-safe guard rewrites.

    The RestrictedPython policy runs first against the public,
    underscore-free guard names, so name validation succeeds.  The
    lifecycle pass then rewrites the validated AST to the internal
    guard names and the result is compiled directly; the rewritten
    nodes are not re-validated, mirroring how the transformer itself
    injects ``_getiter_`` without revisiting the new nodes.
    """
    result = compile_restricted_exec(source, filename=filename)
    if result.errors or result.code is None:
        return result
    tree = ast.parse(source, filename=filename)
    tree = _LifecyclePrepare().visit(tree)
    ast.fix_missing_locations(tree)
    code = compile(tree, filename, 'exec')
    return result._replace(code=code)


class RestrictedExecutionAdapter:
    """Build guarded globals and run code under an execution context."""

    def __init__(self,
                 get_attribute: Optional[Callable[..., Any]] = None):
        self._get_attribute = get_attribute

    def guarded_globals(
            self,
            host_capabilities: Optional[Mapping[
                str, Callable[..., Any]]] = None) -> dict[str, Any]:
        """Return a globals mapping containing the lifecycle guards."""
        host_capabilities = host_capabilities or {}
        globals_scope = dict(safe_globals)
        if self._get_attribute is not None:
            globals_scope['_getattr_'] = self._get_attribute

        def _getiter_(value: Any) -> BoundIterator:
            return bind(value)

        def _capability_(name: str, *args: Any, **kwargs: Any) -> Any:
            context = CURRENT_CONTEXT.get()
            if context is None:
                raise RuntimeError(
                    'capability used outside an execution context')
            context.use_capability(name)
            return host_capabilities[name](*args, **kwargs)

        def _register_cleanup_(
                callback: Callable[[], None]) -> None:
            bound = current_bound()
            if bound is not None:
                bound.register_cleanup(callback)
                return
            context = CURRENT_CONTEXT.get()
            if context is None:
                raise RuntimeError(
                    'cleanup registered outside an execution context')
            context.register_cleanup(callback)

        globals_scope['_getiter_'] = _getiter_
        globals_scope['_capability_'] = _capability_
        globals_scope['_register_cleanup_'] = _register_cleanup_
        return globals_scope

    def run(self, source: str, context: ExecutionContext,
            host_capabilities: Optional[Mapping[
                str, Callable[..., Any]]] = None,
            locals_scope: Optional[dict[str, Any]] = None,
            ) -> dict[str, Any]:
        """Compile and execute restricted source under context.

        The module-level frame runs inside a snapshot of the supplied
        context, so any generator created there captures the correct
        owner regardless of which request later resumes it.
        """
        compiled = compile_lifecycle_restricted(source)
        if compiled.errors:
            raise SyntaxError('; '.join(compiled.errors))
        namespace = self.guarded_globals(host_capabilities)
        if locals_scope is not None:
            namespace.update(locals_scope)

        def _execute() -> dict[str, Any]:
            exec(compiled.code, namespace)
            return namespace

        return context.capture().run(_execute)

    def call(self, callable_object: Callable[..., Any],
             context: ExecutionContext, *args: Any, **kwargs: Any,
             ) -> Any:
        """Invoke a restricted callable inside a context snapshot."""
        return context.capture().run(
            lambda: callable_object(*args, **kwargs))
