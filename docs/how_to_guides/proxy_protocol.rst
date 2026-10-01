PROXY protocol
==============

Hypercorn can accept a PROXY protocol v2 preamble at the start of an
insecure TCP connection. The preamble is only accepted from sources in
``proxy_protocol_trusted_sources``. Other sources cannot inject a
preamble.

The source and destination addresses in a PROXY command replace the
connection peer address in the ASGI ``client`` value. Hypercorn also
adds the parsed command, address family, transport protocol, source and
destination endpoints, and TLV values to the
``hypercorn.proxy_protocol`` scope extension. A LOCAL command keeps the
TCP peer address but still exposes the extension and its TLV values.

Configure trusted sources with host addresses or CIDR networks, for
example,

.. code-block:: python

    config.proxy_protocol_trusted_sources = ["10.0.0.1", "10.0.1.0/24"]

or on the command line,

.. code-block:: console

    $ hypercorn --proxy-protocol-trusted-source 10.0.0.1 module:app

PROXY protocol is not parsed on TLS listeners because the preamble must
be inserted before the TLS handshake. Malformed or oversized headers,
untrusted preambles, and connections that do not complete the preamble
within ``proxy_protocol_timeout`` are closed before the application is
called.
