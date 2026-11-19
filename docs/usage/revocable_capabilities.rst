.. _revocable_capabilities:

Revocable host capabilities
---------------------------

RestrictedPython restricts the *language*, not the *environment* (see
:ref:`security_considerations`).  The objects a host application puts into
``globals`` and ``__builtins__`` are ordinary Python objects.  If restricted
code stores such an object -- by aliasing a name, placing it in a container,
closing over it or suspending it inside a generator -- the host has no handle
on those copies.  Revoking the permission in the host therefore has no
effect: every saved reference keeps invoking the original method.

The :mod:`RestrictedPython.Capabilities` module is an *integration layer* for
that problem.  It does not disable closures or method calls.  Instead the host
wraps every callable it shares with restricted code in a
:class:`~RestrictedPython.RevocableCapability` bound to a
:class:`~RestrictedPython.CapabilityDomain`.

.. testcode:: revocable

    from RestrictedPython import CapabilityDomain
    from RestrictedPython import CapabilityRevokedError
    from RestrictedPython import compile_restricted
    from RestrictedPython import safe_globals

    def increment(counter, amount=1):
        counter["value"] += amount
        return counter["value"]

    counter = {"value": 0}
    domain = CapabilityDomain("session-1")
    bump = domain.grant(lambda amount=1: increment(counter, amount), "bump")

    restricted_globals = dict(safe_globals)
    restricted_globals["bump"] = bump

    byte_code = compile_restricted("result = bump()", "<inline>", "exec")
    local_scope = {}
    exec(byte_code, restricted_globals, local_scope)
    print(local_scope["result"])

.. testoutput:: revocable

    1

Generations
...........

Each domain owns a monotonically increasing generation counter.
``CapabilityDomain.grant()`` stamps a wrapper with the generation current at
grant time; every call re-reads the domain generation *before* entering the
wrapped callable and raises
:class:`~RestrictedPython.CapabilityRevokedError` when the two no longer match.
``CapabilityDomain.revoke()`` advances the counter by one, which invalidates
every wrapper granted earlier, no matter where restricted code stored it.

.. testcode:: revocable

    saved_reference = bump
    domain.revoke()

    try:
        saved_reference()
    except CapabilityRevokedError as error:
        print(type(error).__name__)

.. testoutput:: revocable

    CapabilityRevokedError

A later ``grant()`` produces a fresh wrapper at the new generation.  Old
wrappers stay stale and cannot be revived by the new grant.

Linearization and committed side effects
........................................

The generation check is the single linearization point of a call.  The
optional ``CapabilityDomain.before_revoke`` hook is the linearization point of
a revocation: it runs immediately before the counter advances.

* A call whose check completed before the revocation point runs to
  completion.  Side effects it already committed are kept -- the layer never
  pretends an executed operation could be rolled back.
* A call whose check happens after the revocation point raises
  ``CapabilityRevokedError`` and never reaches the wrapped callable.

The hook makes the ordering deterministic, so tests can schedule operations
without threads, sleeps or external services.

Containers and generators
.........................

References can also hide in containers and suspended generators.  The module
ships guarded counterparts for both:

* :class:`~RestrictedPython.RevocableDict` and
  :class:`~RestrictedPython.RevocableList` remember the generation they were
  created at and gate every read and write on it.  A container saved before a
  revocation stays unusable afterwards, even after the host re-grants
  capabilities at a new generation; fresh containers handed out with the new
  grant work normally.
* :meth:`~RestrictedPython.CapabilityDomain.guarded_iter` and
  :func:`~RestrictedPython.revocable_generator` wrap an iterator or generator
  so that *every* resumed ``__next__`` re-validates the generation, including
  the first one.  A generator suspended across a revocation raises on its
  next resume instead of finishing silently.
* :func:`~RestrictedPython.guarded_getitem` is a generation-checked
  ``_getitem_`` guard for hosts that build their own guarded containers.

Domains are independent
.......................

Create one domain per execution domain (for example one per session or
tenant).  Revoking a domain only changes its own counter.  Wrappers of any
other domain keep their generation and keep working; a policy update can
therefore never spill into a neighbouring execution domain.

Limits
......

This layer makes *host-provided callables* revocable after they have been
shared.  It does not replace the language guards, it cannot take back a
capability the host never wrapped, and RestrictedPython on its own still does
not claim to sandbox arbitrary Python.  Exposing an object continues to
expose everything reachable through it
(see :ref:`guards_only_cover_restricted_source`); wrap the capabilities you
share and keep allowlisting the environment you build.

