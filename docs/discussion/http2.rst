.. _http2:

HTTP/2
======

Hypercorn is based on the excellent `hyper-h2
<https://github.com/python-hyper/hyper-h2>`_ library.

TLS settings
------------

The recommendations in this documentation for the SSL/TLS ciphers and
version are from `RFC 7540 <https://tools.ietf.org/html/rfc7540>`_. As
required in the RFC ``ECDHE+AESGCM`` is the minimal cipher set HTTP/2
and TLSv2 the minimal TLS version servers should support. By default
Hypercorn will use this as the cipher set.

ALPN Protocol
~~~~~~~~~~~~~

The ALPN Protocols should be set to include ``h2`` and ``http/1.1`` as
Hypercorn supports both. It is feasible to omit one to only serve the
other. If these aren't set most clients will assume Hypercorn is a
HTTP/1.1 only server. By default Hypercorn will set h2 and http/1.1 as
the ALPN protocols.

No-TLS
~~~~~~

Most clients, including all the web browsers only support HTTP/2 over
TLS. Hypercorn, however, supports the h2c HTTP/1.1 to HTTP/2 upgrade
process. This allows a client to send a HTTP/1.1 request with a
``Upgrade: h2c`` header that results in the connection being upgraded
to HTTP/2. To test this try

.. code-block:: shell

   $ curl --http2 http://url:port/path

Note that in the absence of either the upgrade header or an ALPN
protocol Hypercorn will assume and treat the connection as HTTP/1.1.

HTTP/2 features
---------------

Hypercorn supports pipeling, flow control, server push, and
prioritisation.

Response prioritisation
-----------------------

Hypercorn advertises a ``http.response.priority`` extension over
HTTP/2 (when ``h2_response_priority`` is enabled, as it is by
default). This allows the app to include a ``priority`` integer in
the ``http.response.start`` message,

.. code-block:: python

    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [...],
            "priority": 10,
        }
    )

The hint controls the order in which already queued DATA frames are
sent on the connection: streams with a higher priority are sent
before lower priority streams, which allows small important
responses to overtake large downloads. Streams that do not declare a
priority are treated as priority 0 whilst any hint is active.

To prevent a steady stream of high priority responses starving lower
priority streams, waiting streams gain an aging boost every time
another stream is sent, so every stream is eventually served.
Whenever no priorities are declared the original client-driven
HTTP/2 priority tree scheduling is used unchanged. Flow control
windows and frame sizes are always respected, and streams that
cannot send do not occupy the scheduler.

Set ``h2_response_priority`` to ``False`` to disable the extension
and ignore any hints.
