Utilities
=========

.. currentmodule:: nacl.utils

.. class:: EncryptedMessage

    A ``bytes`` subclass that holds a message that has been encrypted by a
    :class:`~nacl.secret.SecretBox` or :class:`~nacl.public.Box`. The full
    content of the ``bytes`` object is the combined ``nonce`` and
    ``ciphertext``.

    .. attribute:: nonce

        The nonce used during the encryption of the :class:`EncryptedMessage`.

    .. attribute:: ciphertext

        The ciphertext contained within the :class:`EncryptedMessage`.

.. class:: NonceGenerator

    Abstract base class for nonce generation strategies. A generator is a
    callable taking the required nonce size and returning a fresh nonce.
    Implementations report the uniqueness domain they protect through
    :attr:`scope`.

.. class:: RandomNonceGenerator(scope="nacl.utils.RandomNonceGenerator")

    Nonce strategy backed by :func:`random`. It keeps the nonces it has
    issued and raises :class:`~nacl.exceptions.NonceReuseError` if the
    operating system CSPRNG ever returns a duplicate. Forking and pickling
    do not affect its behaviour.

.. class:: CounterNonceGenerator(prefix, counter=0, nonce_size=None,
                                  scope=None)

    Deterministic nonce strategy producing ``prefix + counter`` nonces,
    with ``counter`` encoded big-endian in the trailing bytes. The prefix
    must be unique per worker/process; :meth:`for_process` builds one from
    a worker id, the PID and random bytes.

    The counter is monotonic and survives serialization together with the
    full nonce history. Exhausting the counter raises
    :class:`~nacl.exceptions.NonceOverflowError`; reusing an issued nonce
    (including after a counter rollback) raises
    :class:`~nacl.exceptions.NonceReuseError` mentioning the :attr:`scope`.
    Using a generator created in another process after a :func:`os.fork`
    raises :class:`~nacl.exceptions.NonceGeneratorForkError`.

    .. method:: for_process(worker_id=b"", nonce_size=None, random_size=8)

        Class method returning a generator with a process unique prefix.

    .. method:: check_nonce(nonce)

        Raises :class:`~nacl.exceptions.NonceReuseError` if ``nonce`` was
        already issued within this generator's scope.

    .. attribute:: prefix

        The fixed prefix prepended to every generated nonce.

    .. attribute:: counter

        The next counter value that will be encoded.

    .. attribute:: scope

        Identifier of the uniqueness domain reported on reuse errors.

.. function:: random(size=32)

    Returns a random bytestring with the given ``size``.

    :param bytes size: The size of the random bytestring.
    :return bytes: The random bytestring.

.. function:: randombytes_deterministic(size, seed, encoder=encoding.RawEncoder)

    Returns ``size`` number of deterministically generated pseudorandom bytes
    from a 32 byte seed.

    :param bytes size: The size of the random bytestring.
    :param bytes seed: The seed for the bytestring. This should be 32 bytes
                            or a TypeError will be thrown.
    :param encoder: The encoder class used to encode the produced bytes.
    :return bytes: The random bytestring.

