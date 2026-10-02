.. module:: itsdangerous.keyed

Versioned Key Envelopes
=======================

.. currentmodule:: itsdangerous

When rotating through many historical keys, the base
:class:`~itsdangerous.signer.Signer` has to try each key in turn to
verify a value. The keyed signers instead wrap each value in a
versioned envelope that carries a key id, so verification selects the
correct key directly.

.. code-block:: python

    from itsdangerous import KeyedSigner
    s = KeyedSigner({"k1": "old-secret", "k2": "new-secret"})
    s.sign("my string")
    b'v1.k2.my string.uN9ylwFNJNvBqWMh2dOaBNl2kXc'

The version and key id are covered by the signature, so changing either
identifier invalidates the value. If the key id is not known,
:exc:`~itsdangerous.keyed.UnknownKeyId` is raised immediately without
trying any other key. Values in the legacy unversioned format are
rejected unless ``accept_legacy=True`` is passed.

Use :meth:`KeyedSigner.unsign_with_info` (or
:meth:`KeyedSerializer.loads_with_info`) to learn which key verified
the value and whether it should be re-signed with the active key:

.. code-block:: python

    info = s.unsign_with_info(token)
    if info.resign_recommended:
        token = s.sign(info.value)

Timed and URL-safe variants mirror the base API, including
``max_age`` and salt isolation:

.. code-block:: python

    from itsdangerous import KeyedURLSafeTimedSerializer
    s = KeyedURLSafeTimedSerializer({"k1": "old", "k2": "new"})
    payload, info = s.loads_with_info(token, max_age=3600)

.. autoclass:: KeyedSigner
    :members:

.. autoclass:: KeyedTimestampSigner
    :members:

.. autoclass:: KeyedSerializer
    :members:

.. autoclass:: KeyedTimedSerializer
    :members:

.. autoclass:: KeyedURLSafeSerializer
    :members:

.. autoclass:: KeyedURLSafeTimedSerializer
    :members:

.. autoclass:: KeyedVerification
    :members:

.. autoexception:: UnknownKeyId
    :members:
