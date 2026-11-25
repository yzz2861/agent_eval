Transactional execution
------------------------

The :mod:`RestrictedPython.transactions` module is an explicit, opt-in
execution layer that collects every write a restricted program makes and
publishes it to the real host objects only after a successful commit.
Default RestrictedPython execution is unchanged: applications keep using
:func:`~RestrictedPython.compile_restricted` exactly as before unless they
deliberately create a :class:`~RestrictedPython.Transaction`.

Why an explicit layer
=====================

A plain ``_write_`` guard decides whether one individual write is allowed,
but it cannot make a whole script atomic. If a later statement raises, or a
guard rejects a statement after earlier writes already happened, the host
application observes a partial modification. The transaction layer removes
that window:

* only data objects and write capabilities that were documented up front
  are reachable for writes;
* writes land on isolated copy-on-write shadows, never on shared host
  objects, while the program runs;
* object identity is preserved through an identity map, so multiple aliases
  of one object and self-referencing containers keep working;
* commit performs a host version check first and applies every shadow
  atomically, restoring all hosts if any part of the apply phase fails;
* exceptions, permission denials and version conflicts never leak a write.

The implementation uses real copies of mutated objects. A shallow copy of
the shared host graph would still expose nested host objects and therefore
does not provide isolation. Only the Python standard library is used; there
is no database.

Documenting data and capabilities
=================================

Create a :class:`~RestrictedPython.Transaction`, then call
:meth:`~RestrictedPython.Transaction.allow_object` for every host object the
restricted program may touch. ``list`` and ``dict`` hosts gain documented
item writes. Other hosts are treated as attribute hosts, and their writable
attributes must be named explicitly.

.. testcode::

    from RestrictedPython import Transaction

    class Account:
        def __init__(self):
            self.balance = 100
            self.tags = ["a"]

    account = Account()
    ledger = {"entries": []}

    transaction = Transaction()
    transaction.allow_object(
        account, name="account",
        writable_attrs=("balance", "tags"))
    transaction.allow_object(ledger, name="ledger")

Reachable nested ``list`` and ``dict`` values are isolated automatically.
Unsupported types (for example ``set``) and callable host attributes are
rejected with :class:`~RestrictedPython.UnsupportedWritable` before any host
side effect can happen. An undocumented write raises
:class:`~RestrictedPython.WritePermissionDenied`.

Executing and committing
========================

:meth:`~RestrictedPython.Transaction.execute` compiles the source with the
standard restricted policy and runs it against guard hooks that route every
read and write through the transaction. The host objects stay untouched
until :meth:`~RestrictedPython.Transaction.commit` succeeds.

.. testcode::

    transaction.execute(
        """
    account.balance = 250
    account.tags = ["b", "c"]
    ledger["entries"].append({"amount": 150})
    """)

    # The real host objects still show the old state here.
    assert account.balance == 100
    assert ledger == {"entries": []}

    transaction.commit()
    assert account.balance == 250
    assert ledger["entries"] == [{"amount": 150}]

Collected writes are available for auditing through
:meth:`~RestrictedPython.Transaction.writes`,
:meth:`~RestrictedPython.Transaction.write_sets` and
:meth:`~RestrictedPython.Transaction.changed_objects` before commit.

Host version checking
=====================

Pass a ``version_getter`` when documenting an object that can change outside
the transaction. The getter is evaluated again during commit; a different
result raises :class:`~RestrictedPython.VersionConflict` and no write is
applied.

.. testcode::

    versions = {"ledger": 7}

    def ledger_version(host):
        return versions["ledger"]

    versioned = Transaction()
    versioned.allow_object(
        ledger, name="ledger", version_getter=ledger_version)

Commit validators run after every version check and before any host changes.
A validator exception is wrapped in :class:`~RestrictedPython.CommitError`
and the hosts stay untouched.

Atomicity for concurrent observers
==================================

The commit phase runs while holding
:attr:`~RestrictedPython.Transaction.lock`, a re-entrant lock. Independent
observers that take the same lock while building a consistent snapshot can
therefore only ever observe the complete old state or the complete new
state, never a half-applied one.

.. testcode::

    with versioned.lock:
        snapshot = list(ledger["entries"])

If the apply phase itself raises (for example because a host setter rejects
a value), every already-applied host is restored from snapshots captured
immediately before the phase, and
:class:`~RestrictedPython.CommitError` is raised.

Lifecycle and convenience API
==============================

A transaction can be discarded explicitly with
:meth:`~RestrictedPython.Transaction.abort` (also available as ``rollback``),
or used as a context manager. The context manager commits when the ``with``
block finishes normally and aborts when it raises.

.. testcode::

    from RestrictedPython import Binding
    from RestrictedPython import transactional_exec

    data = {"n": 0}
    managed, namespace = transactional_exec(
        """
    data["n"] = data["n"] + 10
    """,
        bindings=[Binding(data, "data")])
    assert data == {"n": 10}
    assert managed.committed is True

The exception hierarchy all derives from
:class:`~RestrictedPython.TransactionError`:

* :class:`~RestrictedPython.TransactionStateError` - use after commit/abort;
* :class:`~RestrictedPython.UnsupportedWritable` - type or capability that
  cannot participate, rejected before a side effect;
* :class:`~RestrictedPython.WritePermissionDenied` - write outside the
  documented capabilities;
* :class:`~RestrictedPython.VersionConflict` - concurrent host update;
* :class:`~RestrictedPython.CommitError` - validation or apply failure with
  every host restored.
