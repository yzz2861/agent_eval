##############################################################################
#
# Copyright (c) 2026 Zope Foundation and Contributors.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE
#
##############################################################################
"""Revocable host capabilities for restricted execution domains.

RestrictedPython only restricts the *language*.  The objects a host
application places into the ``globals`` / ``__builtins__`` of a restricted
execution are ordinary Python objects.  When restricted code stores such an
object -- by aliasing a name, putting it into a container, closing over it
or suspending it inside a generator -- the host has no handle on those
copies and cannot take the capability back: every saved reference keeps
calling the original method forever.

This module is an *integration layer* for that problem.  A host creates a
:class:`CapabilityDomain` per execution domain and exposes its capabilities
through :class:`RevocableCapability` wrappers.  Every wrapper is bound to
the generation of its domain at grant time and re-validates against the
current generation at every use, so an alias, a container entry, a closure
cell or a suspended generator all fail with
:class:`CapabilityRevokedError` once the domain is revoked.

Linearization
-------------
The generation check happens *before* the wrapped callable is entered.  A
call that passed the check runs to completion even if the domain is revoked
while it is in flight; already committed side effects are never rolled
back.  Calls arriving after the revocation point observe the new generation
and are refused.  The optional ``before_revoke`` scheduler hook marks the
revocation linearization point explicitly so tests can schedule operations
deterministically without threads or external services.

Scope
-----
Revocation is scoped to a single :class:`CapabilityDomain`.  Revoking one
domain never changes the generation -- and therefore never invalidates the
wrappers -- of any other domain.  This module does not replace the language
guards and does not claim to sandbox arbitrary Python on its own; it only
makes host-provided capabilities revocable after they have been shared with
restricted code.
"""

import collections.abc
import functools
import typing


class CapabilityRevokedError(RuntimeError):
    """Raised when a revoked capability is used.

    Subclasses :class:`RuntimeError` (not :class:`PermissionError`) so that
    hosts can distinguish a generation failure from operating-system level
    access errors.
    """


_T = typing.TypeVar('_T')
_T_ret = typing.TypeVar('_T_ret', covariant=True)


class RevocableCapability(typing.Generic[_T_ret]):
    """A generation-checked wrapper around one host callable.

    The wrapper holds the granted callable and the *generation* the domain
    had at grant time.  It never copies domain state: the current
    generation is read from the domain on every call, which is why
    references saved anywhere -- closure cells, containers, generator
    frames -- all observe a revocation.
    """

    __slots__ = ('_domain', '_generation', '_callable', '__name__',
                 '__qualname__', '__wrapped__')

    def __init__(self,
                 domain: 'CapabilityDomain',
                 callable_: collections.abc.Callable[..., _T_ret],
                 generation: int):
        self._domain = domain
        self._generation = generation
        self._callable = callable_
        functools.update_wrapper(
            self, callable_,
            assigned=('__name__', '__qualname__', '__wrapped__'),
            updated=())

    @property
    def generation(self) -> int:
        """The domain generation this wrapper was granted at."""
        return self._generation

    @property
    def domain(self) -> 'CapabilityDomain':
        """The domain this wrapper belongs to."""
        return self._domain

    @property
    def revoked(self) -> bool:
        """Whether the wrapper is stale relative to its domain."""
        return self._generation != self._domain.generation

    def _check(self) -> None:
        # The linearization point for every individual call.
        if self._generation != self._domain.generation:
            raise CapabilityRevokedError(
                f'capability {self.__name__!r} of domain '
                f'{self._domain.name!r} was revoked')

    def __call__(
            self, *args: typing.Any, **kwargs: typing.Any) -> _T_ret:
        self._check()
        # From here on the call is committed: a concurrent revocation does
        # not interrupt it and its side effects are not rolled back.
        return self._callable(*args, **kwargs)

    def __repr__(self) -> str:
        state = 'revoked' if self.revoked else 'active'
        return (f'<RevocableCapability {self.__name__!r} '
                f'generation={self._generation} {state}>')


class CapabilityDomain:
    """An independent revocation scope for host capabilities.

    Each restricted execution domain gets its own instance.  A domain owns
    a monotonically increasing generation counter; :meth:`grant` stamps a
    :class:`RevocableCapability` with the current generation, and
    :meth:`revoke` advances the generation, instantly invalidating every
    wrapper granted before that point.
    """

    __slots__ = ('name', '_generation', 'before_revoke')

    def __init__(self, name: str = 'capability-domain'):
        self.name = name
        self._generation = 0
        # Optional scheduler hook.  Called with the domain immediately
        # before the generation is advanced; deterministic tests use it to
        # interleave another operation at the revocation linearization
        # point.  Production hosts normally leave it unset.
        self.before_revoke: collections.abc.Callable[
            ['CapabilityDomain'], None] | None = None

    @property
    def generation(self) -> int:
        """The current generation.  Changes on every revocation."""
        return self._generation

    @property
    def revoked(self) -> bool:
        """Whether at least one revocation has happened."""
        return self._generation != 0

    def grant(
            self,
            callable_: collections.abc.Callable[..., _T_ret],
            name: str | None = None) -> RevocableCapability[_T_ret]:
        """Return a revocable wrapper for *callable_*.

        The wrapper is valid for the current generation only.  Re-granting
        after a revocation produces a fresh wrapper at the new generation;
        older wrappers stay stale and cannot be revived by the new grant.
        """
        if name is not None:
            try:
                callable_.__name__ = name  # type: ignore[attr-defined]
            except (AttributeError, TypeError):
                # Builtins and other read-only callables keep their name.
                pass
        return RevocableCapability(self, callable_, self._generation)

    def revoke(self) -> None:
        """Advance the generation, invalidating every earlier wrapper.

        The revocation linearization point is *after* the optional
        ``before_revoke`` hook returns and *before* the counter is updated.
        Wrappers whose check ran before this point continue their call;
        wrappers checked afterwards fail.
        """
        if self.before_revoke is not None:
            self.before_revoke(self)
        self._generation += 1

    def check(self, capability: RevocableCapability[typing.Any]) -> None:
        """Raise unless *capability* is current for this domain."""
        if not isinstance(capability, RevocableCapability):
            raise TypeError(
                f'expected a RevocableCapability, got {type(capability)!r}')
        if capability.domain is not self:
            raise ValueError(
                f'capability {capability.__name__!r} belongs to domain '
                f'{capability.domain.name!r}, not {self.name!r}')
        capability._check()

    def guarded_iter(
            self,
            iterable: collections.abc.Iterable[_T]
    ) -> collections.abc.Iterator[_T]:
        """Return an iterator that re-validates the domain on every step.

        A generator or iterator saved by restricted code resumes through
        ``next()``; wrapping it here ensures each resumed ``__next__`` is
        gated by the current generation instead of only the first one.
        """
        iterator = iter(iterable)
        generation = self._generation

        def _guarded_iter() -> collections.abc.Iterator[_T]:
            while True:
                # Re-read the generation on every resume: a generator
                # suspended at a ``yield`` must notice a revocation that
                # happened while it was suspended.
                if self.generation != generation:
                    raise CapabilityRevokedError(
                        f'iterator of domain {self.name!r} was revoked')
                try:
                    value = next(iterator)
                except StopIteration:
                    return
                yield value

        return _guarded_iter()


def guarded_getitem(domain: CapabilityDomain,
                    container: collections.abc.Mapping[typing.Any, _T]
                    | collections.abc.Sequence[_T],
                    key: typing.Any,
                    generation: int | None = None) -> _T:
    """Generation-checked ``container[key]`` for restricted containers.

    When *generation* is given it is compared against the domain's current
    generation, so a guard function bound at grant time stays stale after a
    revocation and after a later re-grant.  Without it the check simply
    asks whether the domain has ever been revoked.
    """
    expected = domain.generation if generation is None else generation
    if expected != domain.generation:
        raise CapabilityRevokedError(
            f'domain {domain.name!r} is revoked; container access denied')
    return container[key]


class _RevocableContainer:
    """Shared generation gate for the guarded container types."""

    _domain: 'CapabilityDomain'
    _generation: int

    def _check(self) -> None:
        if self._generation != self._domain.generation:
            raise CapabilityRevokedError(
                f'domain {self._domain.name!r} is revoked; '
                'container access denied')


class RevocableDict(_RevocableContainer,
                    collections.abc.MutableMapping[typing.Any, typing.Any]):
    """A mapping whose every access is gated by a capability domain.

    Hosts expose this instead of a plain ``dict`` when restricted code must
    be able to store and later retrieve granted capabilities.  Every read
    and write path (``[]``, ``get``, iteration, ``in``, ``len``) validates
    the current generation first, so a capability saved in the container
    cannot be used after the domain is revoked even though the entry itself
    still exists.

    The gate stores the generation the container was created at and
    compares it against the domain's current generation on every access.
    Containers saved before a revocation therefore stay unusable after the
    host re-grants capabilities at a new generation, while fresh containers
    handed out with the new grant work normally.
    """

    __slots__ = ('_domain', '_generation', '_data')

    def __init__(self,
                 domain: CapabilityDomain,
                 data: collections.abc.Mapping[typing.Any, typing.Any]
                 | None = None):
        self._domain = domain
        self._generation = domain.generation
        self._data: dict[typing.Any, typing.Any] = {}
        if data is not None:
            self._data.update(data)

    def __getitem__(self, key: typing.Any) -> typing.Any:
        self._check()
        return self._data[key]

    def __setitem__(self, key: typing.Any, value: typing.Any) -> None:
        self._check()
        self._data[key] = value

    def __delitem__(self, key: typing.Any) -> None:
        self._check()
        del self._data[key]

    def __iter__(self) -> collections.abc.Iterator[typing.Any]:
        self._check()
        return iter(self._data)

    def __len__(self) -> int:
        self._check()
        return len(self._data)


class RevocableList(_RevocableContainer,
                    collections.abc.MutableSequence[_T]):
    """Sequence counterpart of :class:`RevocableDict`."""

    __slots__ = ('_domain', '_generation', '_data')

    def __init__(self,
                 domain: CapabilityDomain,
                 data: collections.abc.Iterable[_T] | None = None):
        self._domain = domain
        self._generation = domain.generation
        self._data: list[_T] = [] if data is None else list(data)

    def __getitem__(self, index: typing.Any) -> _T:
        self._check()
        return self._data[index]

    def __setitem__(self, index: typing.Any, value: _T) -> None:
        self._check()
        self._data[index] = value

    def __delitem__(self, index: typing.Any) -> None:
        self._check()
        del self._data[index]

    def __len__(self) -> int:
        self._check()
        return len(self._data)

    def insert(self, index: int, value: _T) -> None:
        self._check()
        self._data.insert(index, value)


def revocable_generator(
        domain: CapabilityDomain,
        generator: collections.abc.Iterator[_T]
) -> collections.abc.Iterator[_T]:
    """Wrap a generator so each resume checks the domain generation.

    Restricted code that stores a generator object (for example the result
    of a generator expression) resumes it later with ``next()``.  The
    wrapper delegates to :meth:`CapabilityDomain.guarded_iter` so a
    generator suspended across a revocation raises
    :class:`CapabilityRevokedError` on its next resume instead of finishing
    normally.
    """
    if not isinstance(generator, collections.abc.Iterator):
        raise TypeError(
            f'expected an iterator, got {type(generator)!r}')
    return domain.guarded_iter(generator)
