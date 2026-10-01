API Reference
=============

.. module:: jwt

.. autofunction:: encode(payload, key, algorithm="HS256", headers=None, json_encoder=None) -> str

.. autofunction:: decode(jwt, key="", algorithms=None, options=None, audience=None, issuer=None, leeway=0) -> dict[str, typing.Any]

.. autofunction:: decode_complete(jwt, key="", algorithms=None, options=None, verify=None, detached_payload=None, audience=None, issuer=None, subject=None, leeway=0) -> dict[str, typing.Any]

.. autoclass:: PyJWT
    :class-doc-from: init
    :members:

.. autoclass:: PyJWK
    :class-doc-from: init
    :members:

    .. property:: algorithm_name

        :type: str

        The name of the algorithm used by the key.

    .. property:: Algorithm

        The :py:class:`Algorithm` class associated with the key.

.. autoclass:: PyJWKSet
    :members:

.. autoclass:: PyJWKClient
    :class-doc-from: init
    :members:

.. note:: TODO: Finish documenting PyJWS class
.. module:: jwt.api_jws

.. autoclass:: jwt.api_jws.PyJWS
    :members:

JWS JSON Serialization
~~~~~~~~~~~~~~~~~~~~~~

:meth:`jwt.api_jws.PyJWS.encode_general` creates the General JWS JSON
Serialization with one or more independent signatures. Each signer provides its
own protected and unprotected headers, key, and algorithm. Use
:meth:`jwt.api_jws.PyJWS.encode_flattened` for the single-signature Flattened
serialization.

Verification independently validates every signature and reports each result in
``signatures``. ``required_signers`` identifies the ``kid`` values that must
validate, while ``minimum_signers`` requires that number of distinct valid
signers. Repeated signatures from the same ``kid`` count once. If the caller's
policy is not met, ``decode_json()`` raises and the complete result hides the
payload by setting it to ``None``.

Signing keys are supplied by ``kid`` with the ``keys`` argument, for example
``keys={"kid-a": (key_a, ["RS256"]), "kid-b": (key_b, ["ES256"])}``. Each
algorithm allow-list is applied independently to the corresponding signature.

Algorithms
----------

.. automodule:: jwt.algorithms
    :members: Algorithm, AllowedPrivateKeys, AllowedPublicKeys


Types
----------

.. module:: jwt.types
    :synopsis: Type validation used in the JWT API
.. autoclass:: jwt.types.SigOptions
    :members:
    :undoc-members:
.. autoclass:: jwt.types.Options
    :members:
    :undoc-members:

Warnings
----------

.. automodule:: jwt.warnings
    :members:
    :show-inheritance:

Exceptions
----------

.. automodule:: jwt.exceptions
    :members:
    :inherited-members:
    :show-inheritance:
