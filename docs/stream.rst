.. module:: itsdangerous.stream

Record Streams
==============

A :class:`RecordStreamSigner` signs a sequence of byte-string records.
The wire format is versioned and uses stream-specific signing salts, so
an ordinary :class:`~itsdangerous.signer.Signer` token is never accepted
as a stream frame.

Each stream starts with a random identifier. A record frame authenticates
that identifier, its index, the previous frame's signature, and its
payload. The final frame authenticates the total number of records.

Records may be emitted before the final frame is received, but the reader
is only marked complete after the final frame is verified. Calling
:meth:`StreamReader.eof` also checks that there is no partial frame left
in the buffer.

.. code-block:: python

    from itsdangerous import RecordStreamSigner

    signer = RecordStreamSigner("secret-key")
    data = signer.sign_stream([b"one", b"two"])

    reader = signer.reader()
    records = reader.feed(data)
    reader.eof()
    assert records == [b"one", b"two"]
    assert reader.complete

The reader accepts data split at arbitrary byte boundaries. After early
EOF, a duplicate or replaced final frame, reordered records, a frame from
another stream, or any other validation error, it raises
:exc:`~itsdangerous.exc.BadRecordStream` and cannot produce or accept more
records.

.. autoclass:: RecordStreamSigner
    :members:

.. autoclass:: StreamWriter
    :members:

.. autoclass:: StreamReader
    :members:
