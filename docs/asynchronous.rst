.. module:: itsdangerous.asynchronous

Async Signing Services
======================

.. versionadded:: 2.3

Sometimes the secret key is not available locally, for example when
it is held by a remote signing service or key management system. The
sync signers cannot be used in that case because they derive keys
and sign locally. The async serializers instead delegate signing and
verification to an object implementing the :class:`AsyncSigner`
protocol, which is only given the exact bytes to authenticate and a
``salt`` describing the purpose of the signature. The secret key
never leaves the service.

The wire format is identical to the sync serializers, so a value
signed by one can be verified by the other if the service uses the
same key, salt, and algorithm.

.. code-block:: python

    from itsdangerous.asynchronous import AsyncSerializer

    s = AsyncSerializer(my_remote_signer, salt="activation")
    signed = await s.dumps({"id": 42})
    data = await s.loads(signed)

Only :class:`.BadSignature` indicates invalid data. If the service
cannot complete a request, the signer should raise
:class:`.SignerUnavailable`; if the call is cancelled,
``asyncio.CancelledError`` propagates. Neither is turned into a
signature failure, and neither causes unverified data to be
returned.

.. autoclass:: AsyncSigner
    :members:

.. autoclass:: AsyncSerializer
    :members:

.. autoclass:: AsyncTimedSerializer
    :members:

.. autoclass:: AsyncURLSafeSerializer

.. autoclass:: AsyncURLSafeTimedSerializer
