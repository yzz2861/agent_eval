"""Lifecycle-bound execution contexts for restricted generators.

A restricted generator (and every iterator derived from it) is bound to
the policy and capability context that was active when it was created.
It is later re-entered inside a copy of *that* context instead of the
ambient context of the request that happens to resume it.  Once the
owning context has been permanently revoked, the generator may only be
closed, which performs registered, trusted cleanup and never executes
business side effects again.

The module deliberately uses only the standard library and contains no
asynchronous primitives.
"""

from __future__ import annotations

import contextvars
import types
import threading
from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Callable
from typing import Iterator
from typing import Optional
from typing import Union


#: Ambient execution context for the current frame.
CURRENT_CONTEXT: contextvars.ContextVar[
    Optional['ExecutionContext']
] = contextvars.ContextVar('restricted_execution_context', default=None)

#: The bound object that owns the currently running restricted frame.
CURRENT_BOUND: contextvars.ContextVar[
    Optional['BoundIterator']
] = contextvars.ContextVar('restricted_current_bound', default=None)

#: True while a frame runs as part of controlled cleanup (``close``).
CLEANUP_MODE: contextvars.ContextVar[bool] = contextvars.ContextVar(
    'restricted_cleanup_mode', default=False)


class LifecycleError(RuntimeError):
    """Base class for lifecycle violations of bound objects."""


class ContextSuspendedError(LifecycleError):
    """The owning context is temporarily suspended and may be resumed."""


class ContextRevokedError(LifecycleError):
    """The owning request has ended; the context is permanently gone."""


class CapabilityDeniedError(LifecycleError):
    """A capability is unknown, exhausted or forbidden during cleanup."""


@dataclass(frozen=True)
class Policy:
    """Immutable policy captured at object-creation time.

    ``capabilities`` maps a capability name to its invocation budget;
    ``None`` means the capability is allowed without a numeric limit.
    """

    name: str
    capabilities: frozenset[str]
    budgets: dict[str, Optional[int]] = field(default_factory=dict)


#: Lifecycle state of an :class:`ExecutionContext`.
ACTIVE = 'active'
SUSPENDED = 'suspended'
REVOKED = 'revoked'

class ExecutionContext:
    """A request-scoped policy, capability and cleanup container.

    States distinguish a temporary suspension (the request may continue
    later) from a permanent revocation (the request has ended).  All
    state is guarded by a lock so that a bound object handed to another
    thread cannot mutate counters concurrently.
    """

    def __init__(self, policy: Policy):
        self.policy = policy
        self.state = ACTIVE
        self.capability_usage: dict[str, int] = {
            name: 0 for name in policy.capabilities
        }
        #: Trusted cleanup callbacks for the whole request.
        self._cleanups: list[Callable[[], None]] = []
        #: Bound objects that must be closed on revocation.
        self._bound: list['BoundIterator'] = []
        self.cleanup_count = 0
        self.revocation_errors: list[BaseException] = []
        self._lock = threading.RLock()

    # -- introspection -------------------------------------------------

    @property
    def is_active(self) -> bool:
        return self.state == ACTIVE

    @property
    def is_suspended(self) -> bool:
        return self.state == SUSPENDED

    @property
    def is_revoked(self) -> bool:
        return self.state == REVOKED

    def check_usable(self) -> None:
        """Raise unless business work is permitted right now."""
        if self.state == SUSPENDED:
            raise ContextSuspendedError(
                f'context {self.policy.name!r} is suspended')
        if self.state == REVOKED:
            raise ContextRevokedError(
                f'context {self.policy.name!r} has been revoked')

    # -- state transitions ---------------------------------------------

    def suspend(self) -> None:
        """Temporarily park the context; it can be resumed later."""
        with self._lock:
            if self.state != ACTIVE:
                raise LifecycleError(
                    f'cannot suspend context in state {self.state!r}')
            self.state = SUSPENDED

    def resume(self) -> None:
        """Reactivate a previously suspended context."""
        with self._lock:
            if self.state != SUSPENDED:
                raise LifecycleError(
                    f'cannot resume context in state {self.state!r}')
            self.state = ACTIVE

    def revoke(self) -> list[BaseException]:
        """Permanently end the request and close every bound object.

        Cleanup errors are captured instead of aborting the remaining
        cleanups; they are also returned for caller inspection.
        """
        with self._lock:
            if self.state == REVOKED:
                return list(self.revocation_errors)
            self.state = REVOKED
            bound = list(self._bound)
            self._bound.clear()
        for bound_object in bound:
            try:
                bound_object.close()
            except BaseException as exc:  # cleanup must continue
                self.revocation_errors.append(exc)
        for cleanup in tuple(self._cleanups):
            try:
                self._run_cleanup(cleanup)
            except BaseException as exc:
                self.revocation_errors.append(exc)
        self._cleanups.clear()
        return list(self.revocation_errors)

    # -- capabilities and cleanup --------------------------------------

    def use_capability(self, name: str) -> None:
        """Charge one invocation of host capability ``name``."""
        if CLEANUP_MODE.get():
            raise CapabilityDeniedError(
                f'capability {name!r} is forbidden during cleanup')
        self.check_usable()
        with self._lock:
            if name not in self.policy.capabilities:
                raise CapabilityDeniedError(
                    f'capability {name!r} is not granted by policy '
                    f'{self.policy.name!r}')
            used = self.capability_usage.get(name, 0)
            budget = self.policy.budgets.get(name)
            if budget is not None and used >= budget:
                raise CapabilityDeniedError(
                    f'capability {name!r} budget {budget} exhausted')
            self.capability_usage[name] = used + 1

    def record_cleanup(self, label: str = 'cleanup') -> None:
        """Account for one executed cleanup action."""
        with self._lock:
            self.cleanup_count += 1

    def register_cleanup(self, callback: Callable[[], None]) -> None:
        """Register a trusted request-level cleanup callback."""
        with self._lock:
            if self.state == REVOKED:
                raise ContextRevokedError(
                    'cannot register cleanup on a revoked context')
            self._cleanups.append(callback)

    def _track(self, bound_object: 'BoundIterator') -> None:
        with self._lock:
            self._bound.append(bound_object)

    def _untrack(self, bound_object: 'BoundIterator') -> None:
        with self._lock:
            try:
                self._bound.remove(bound_object)
            except ValueError:
                pass

    def _run_cleanup(self, callback: Callable[[], None]) -> None:
        # Trusted cleanup is invoked directly.  Business capabilities
        # remain unavailable because ``CLEANUP_MODE`` stays enabled.
        self.record_cleanup(getattr(callback, '__name__', 'cleanup'))
        token = CLEANUP_MODE.set(True)
        try:
            callback()
        finally:
            CLEANUP_MODE.reset(token)

    # -- contextvar binding --------------------------------------------

    def capture(self) -> contextvars.Context:
        """Return a frozen context snapshot rooted at this context."""
        snapshot = contextvars.copy_context()
        snapshot.run(CURRENT_CONTEXT.set, self)
        snapshot.run(CLEANUP_MODE.set, False)
        return snapshot


def current_context() -> Optional[ExecutionContext]:
    """Return the ambient execution context, if any."""
    return CURRENT_CONTEXT.get()


def current_bound() -> Optional['BoundIterator']:
    """Return the bound object owning the running frame, if any."""
    return CURRENT_BOUND.get()


# Thread-local stack of snapshots currently entered on this thread.
# Identical nested snapshots reuse the outer ``Context.run`` frame so
# re-entrant iteration (including ``yield from``) never enters the same
# immutable context twice.
_active_snapshots = threading.local()


def _snapshot_stack() -> list[contextvars.Context]:
    stack = getattr(_active_snapshots, 'stack', None)
    if stack is None:
        stack = []
        _active_snapshots.stack = stack
    return stack


class BoundIterator:
    """Iterator bound for its whole life to one execution context.

    Every re-entry (``next``/``send``, ``throw`` and ``close``) checks
    the owning lifecycle and runs inside the context captured at
    creation time, so ambient ``ContextVar`` values of unrelated
    requests never leak into the restricted frame.
    """

    def __init__(self, iterator: Iterator[Any], owner: ExecutionContext):
        self._iterator = iterator
        self.owner = owner
        self.policy = owner.policy
        self._snapshot = owner.capture()
        self._lock = threading.RLock()
        self._started = False
        self._closed = False
        self._exhausted = False
        self._cleanups: list[Callable[[], None]] = []
        self._is_generator = hasattr(iterator, 'send')
        owner._track(self)

    # -- protocol ------------------------------------------------------

    def __iter__(self) -> 'BoundIterator':
        return self

    def __next__(self) -> Any:
        return self.send(None)

    def send(self, value: Any) -> Any:
        with self._lock:
            self._check_resumable()
            if not self._is_generator:
                if value is not None:
                    raise TypeError(
                        'can only send(None) to a non-generator iterator')
                self._started = True
                try:
                    return self._enter(lambda: next(self._iterator))
                except StopIteration:
                    self._finish()
                    raise
            if not self._started and value is not None:
                raise TypeError(
                    "can't send non-None value to a just-started "
                    'generator')
            self._started = True
            try:
                return self._enter(
                    lambda: self._iterator.send(value))
            except StopIteration:
                self._finish()
                raise

    def throw(
        self,
        exc_type: Union[BaseException, type[BaseException]],
        exc_value: Optional[BaseException] = None,
        traceback: Any = None,
    ) -> Any:
        with self._lock:
            self._check_resumable()
            if not self._is_generator:
                self._finish()
                if isinstance(exc_type, BaseException):
                    raise exc_type
                raise exc_type(exc_value)
            if isinstance(exc_type, BaseException):
                throw_args: tuple[Any, ...] = (exc_type,)
            elif exc_value is None:
                throw_args = (exc_type(),)
            else:
                throw_args = (exc_type, exc_value, traceback)
            self._started = True
            try:
                return self._enter(
                    lambda: self._iterator.throw(*throw_args))
            except StopIteration:
                # The frame terminated while handling the thrown value.
                self._finish()
                raise
            # Any other exception escaped the frame and propagates; the
            # generator remains suspended and keeps its lifecycle state.

    def close(self) -> None:
        """Controlled teardown; always safe to call more than once."""
        with self._lock:
            if self._closed or self._exhausted:
                return
            self._closed = True
            self.owner._untrack(self)
            if not self._is_generator:
                self._run_owned_cleanups()
                return
            self.owner.record_cleanup('generator-close')
            try:
                self._enter(self._iterator.close, cleanup=True)
            except (GeneratorExit, StopIteration):
                # Normal generator contract for ``close``.
                pass
            finally:
                self._run_owned_cleanups()

    # -- cleanup registration ------------------------------------------

    def register_cleanup(self, callback: Callable[[], None]) -> None:
        """Attach a trusted cleanup callback to this object."""
        with self._lock:
            if self._closed or self._exhausted:
                raise LifecycleError(
                    'cannot register cleanup on a finished iterator')
            self._cleanups.append(callback)

    def _run_owned_cleanups(self) -> None:
        for callback in tuple(self._cleanups):
            self.owner._run_cleanup(callback)
        self._cleanups.clear()

    # -- internals -----------------------------------------------------

    def _check_resumable(self) -> None:
        if self._closed:
            raise ContextRevokedError(
                'iterator has already been closed')
        if self._exhausted:
            raise StopIteration
        self.owner.check_usable()

    def _finish(self) -> None:
        if self._exhausted:
            return
        self._exhausted = True
        self._closed = True
        self.owner._untrack(self)
        self._run_owned_cleanups()

    def _enter(self, operation: Callable[[], Any],
               cleanup: bool = False) -> Any:
        """Run ``operation`` in the captured owning context."""
        stack = _snapshot_stack()
        if stack and stack[-1] is self._snapshot:
            # Re-entrant call inside the same owning frame.
            if cleanup:
                token = CLEANUP_MODE.set(True)
                try:
                    return operation()
                finally:
                    CLEANUP_MODE.reset(token)
            return operation()

        def _run() -> Any:
            bound_token = CURRENT_BOUND.set(self)
            cleanup_token = CLEANUP_MODE.set(cleanup)
            try:
                return operation()
            finally:
                CLEANUP_MODE.reset(cleanup_token)
                CURRENT_BOUND.reset(bound_token)

        stack.append(self._snapshot)
        try:
            return self._snapshot.run(_run)
        finally:
            stack.pop()


def bind(iterator: Iterator[Any],
         owner: Optional[ExecutionContext] = None) -> BoundIterator:
    """Bind an iterator to an execution context.

    The owner defaults to the ambient context.  Binding an already
    bound object returns the same object so nested ``yield from``
    chains cannot rebind an object to a different request.
    """
    if isinstance(iterator, BoundIterator):
        return iterator
    if owner is None:
        owner = CURRENT_CONTEXT.get()
    if owner is None:
        raise LifecycleError(
            'no execution context is active; bind() requires an owner')
    return BoundIterator(iter(iterator), owner)
