.. module:: itsdangerous.signer

Signing Interface
=================

The most basic interface is the signing interface. The :class:`Signer`
class can be used to attach a signature to a specific string:

.. code-block:: python

    from itsdangerous import Signer
    s = Signer("secret-key")
    s.sign("my string")
    b'my string.wh6tMHxLgJqB6oY1uT73iMlyrOA'

The signature is appended to the string, separated by a dot. To validate
the string, use the :meth:`~Signer.unsign` method:

.. code-block:: python

    s.unsign(b"my string.wh6tMHxLgJqB6oY1uT73iMlyrOA")
    b'my string'

If unicode strings are provided, an implicit encoding to UTF-8 happens.
However after unsigning you won't be able to tell if it was unicode or
a bytestring.

If the value is changed, the signature will no longer match, and
unsigning will raise a :exc:`~itsdangerous.exc.BadSignature` exception:

.. code-block:: python

    s.unsign(b"different string.wh6tMHxLgJqB6oY1uT73iMlyrOA")
    Traceback (most recent call last):
      ...
    BadSignature: Signature does not match

To record and validate the age of a signature, see :doc:`/timed`.

.. autoclass:: Signer
    :members:


Signing Algorithms
------------------

.. autoclass:: NoneAlgorithm

.. autoclass:: HMACAlgorithm
-------------


Async Signing

If the secret key is held by a remote signing service and is not
available locally, use :class:`AsyncSigner` with an
:class:`AsyncSignerBackend` implementation. The backend only receives
the exact bytes to authenticate and a ``purpose`` (the salt), and
returns a signature or verification result. The same encoding
conventions as :class:`Signer` are used, so values are interchangeable
if the service uses the same key and algorithm.

.. code-block:: python

    from itsdangerous import AsyncSigner

    s = AsyncSigner(my_remote_backend)
    signed = await s.sign("my string")
    assert await s.unsign(signed) == b"my string"

If the service cannot be reached,
:exc:`~itsdangerous.exc.SignerUnavailable` is raised. This is distinct
from :exc:`~itsdangerous.exc.BadSignature`, and cancellation
propagates as :exc:`asyncio.CancelledError`; neither is silently
treated as an invalid signature.

.. autoclass:: AsyncSignerBackend
    :members:

.. autoclass:: AsyncSigner
    :members:
