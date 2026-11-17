.. module:: itsdangerous.signer

Signing Interface
=================

The most basic interface is the signing interface. The :class:`Signer`
class can be used to attach a signature to a specific string:

.. code-block:: python

    from itsdangerous import Signer
    s = Signer("secret-key")
    s.sign("my string")
    b'my string.85dbe15dwh6tMHxLgJqB6oY1uT73iMlyrOA'

The signature is appended to the string, separated by a dot. The
signature starts with a short key id (``85dbe15d`` here) that identifies
which key produced it, followed by the base64-encoded signature itself.
To validate the string, use the :meth:`~Signer.unsign` method:

.. code-block:: python

    s.unsign(b"my string.85dbe15dwh6tMHxLgJqB6oY1uT73iMlyrOA")
    b'my string'

If unicode strings are provided, an implicit encoding to UTF-8 happens.
However after unsigning you won't be able to tell if it was unicode or
a bytestring.

If the value is changed, the signature will no longer match, and
unsigning will raise a :exc:`~itsdangerous.exc.BadSignature` exception:

.. code-block:: python

    s.unsign(b"different string.85dbe15dwh6tMHxLgJqB6oY1uT73iMlyrOA")
    Traceback (most recent call last):
      ...
    BadSignature: Signature does not match

To record and validate the age of a signature, see :doc:`/timed`.

.. _key-rotation:

Key Rotation
------------

A list of keys, oldest to newest, can be passed as the ``secret_key``
to rotate keys over time. The newest (last) key is used to sign, and
all keys are accepted when verifying.

.. code-block:: python

    s = Signer(["old-key", "new-key"])

Each signature starts with the short :meth:`~Signer.key_id` of the key
that produced it. When unsigning, the id selects the matching key
directly, so only one key is tried. If the id is missing (a signature
made by an older version) or names an unknown key, verification falls
back to trying every key, comparing in constant time so the timing does
not reveal which key, if any, matched.

To retire an old key, remove it from the list once all data signed with
it has expired. For example, when using :class:`~itsdangerous.timed.
TimestampSigner` with ``max_age``, a key can be removed once it is older
than that age. Signatures made with a removed key have an unknown id
and will be rejected.

.. code-block:: python

    # Deploy with both keys, new tokens use "new-key".
    s = Signer(["old-key", "new-key"])

    # After everything signed with "old-key" has expired, retire it.
    s = Signer(["new-key"])

Use :meth:`~Signer.key_ids` to inspect which keys a signer still
accepts, and :meth:`~Signer.get_key_id` to find the id a key will have
before adding or removing it. Never remove the newest key before its
replacement is deployed everywhere, or new signatures will be rejected.

.. autoclass:: Signer
    :members:


Signing Algorithms
------------------

.. autoclass:: NoneAlgorithm

.. autoclass:: HMACAlgorithm
