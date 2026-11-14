.. _settings-chapter:

========
Settings
========

``RATELIMIT_CACHE_PREFIX``
--------------------------

An optional cache prefix for ratelimit keys (in addition to the ``PREFIX``
value defined on the cache backend). Defaults to ``'rl:'``.

``RATELIMIT_HASH_ALGORITHM``
-----------------------------

An optional functionion to overide the default hashing algorithm used to derive the cache
key. Defaults to ``'hashlib.sha256'``.

``RATELIMIT_ENABLE``
--------------------

Set to ``False`` to disable rate-limiting across the board. Defaults to
``True``.

May be useful during tests with Django's |override_settings|_ testing tool,
for example:

.. code-block:: python

    from django.test import override_settings

    with override_settings(RATELIMIT_ENABLE=False):
        result = call_the_view()

.. |override_settings| replace:: ``override_settings()``
.. _override_settings: https://docs.djangoproject.com/en/2.0/topics/testing/tools/#django.test.override_settings.

``RATELIMIT_USE_CACHE``
-----------------------

.. warning::
   `django_ratelimit` requires a Django cache backend that supports _`atomic
   increment` operations. The Memcached and Redis backends do, but the database
   backend does not.

The name of the cache (from the ``CACHES`` dict) to use. Defaults to
``'default'``.

``RATELIMIT_VIEW``
------------------

The string import path to a view to use when a request is ratelimited, in
conjunction with ``RatelimitMiddleware``, e.g. ``'myapp.views.ratelimited'``.
Has no default - you must set this to use ``RatelimitMiddleware``.

``RATELIMIT_FAIL_OPEN``
-----------------------

Whether to allow requests when the cache backend fails. Defaults to ``False``.

``RATELIMIT_IP_META_KEY``
-------------------------

Set the source of the client IP address in the request.META object. Defaults to
``None``.

There are several potential values:

``None``
  Use ``request.META['REMOTE_ADDR']`` as the source of the client IP address.

A callable object
  If set to a callable, the callable will be passed the full ``request``
  object. The callable must return the client IP address. For example:
  ``RATELIMIT_IP_META_KEY = lambda r: r.META['HTTP_X_CLIENT_IP']``

A dotted path to a callable
  Any string containing a ``.`` will be treated as a dotted path to a callable,
  which will be imported and called on the ``request`` object, as above.

Any other string
  Any other string will be treated as a key for the ``request.META`` object,
  e.g. ``RATELIMIT_IP_META_KEY = 'HTTP_X_REAL_IP'``

``RATELIMIT_TRUSTED_PROXIES``
-----------------------------

An explicit opt-in list of reverse proxy IP addresses or CIDR networks that
are allowed to provide the client IP address. A single address or network may
be given as a string; multiple values must be given as a list or tuple of
strings, e.g. ``["10.0.0.1", "10.0.0.0/24"]``. Defaults to ``None``.

This setting only takes effect together with
``RATELIMIT_CLIENT_IP_HEADER``. When either is unset, the legacy
``RATELIMIT_IP_META_KEY``/``REMOTE_ADDR`` behavior is preserved unchanged.
When both are set, they take precedence over ``RATELIMIT_IP_META_KEY``.

The immediate peer (``REMOTE_ADDR``) must belong to this set before the
configured header is read. Headers sent by a direct or untrusted connection
are ignored, so they cannot be used to spoof the rate limit bucket.

``RATELIMIT_CLIENT_IP_HEADER``
------------------------------

The ``request.META`` key holding the client IP supplied by a trusted proxy.
Defaults to ``None``. Use a single-value header key such as
``"HTTP_X_REAL_IP"``, or ``"HTTP_X_FORWARDED_FOR"`` for a forwarding
chain. Only consulted when ``REMOTE_ADDR`` matches
``RATELIMIT_TRUSTED_PROXIES``.

For a single-value header, a value containing a comma or the simultaneous
presence of an ``X-Forwarded-For`` header is treated as ambiguous: the request
fails closed instead of silently choosing one address.

For ``HTTP_X_FORWARDED_FOR``, the chain is parsed from right to left, skipping
addresses that belong to ``RATELIMIT_TRUSTED_PROXIES``, and the first
untrusted address is used as the client IP. The leftmost value is never
trusted on its own.

Empty segments, embedded ports, IPv6 zone identifiers, control characters,
unparseable addresses or chains longer than 64 hops make the client IP
unavailable. In that case rate limiting fails closed (``should_limit=True``)
rather than falling back to an attacker-controlled bucket; this is independent
of ``RATELIMIT_FAIL_OPEN``, which only applies to cache failures. Resolved
addresses are normalized, including IPv6 case/compression and IPv4-mapped
IPv6 addresses, before the configured IPv4/IPv6 masks are applied.

``RATELIMIT_IPV4_MASK``
-----------------------

IPv4 mask for IP-based rate limit. Defaults to ``32`` (which is no masking)

``RATELIMIT_IPV6_MASK``
-----------------------

IPv6 mask for IP-based rate limit. Defaults to ``64`` (which mask the last 64 bits).
Typical end site IPv6 assignment are from /48 to /64.

``RATELIMIT_EXCEPTION_CLASS``
-----------------------------

A custom exception class, or a dotted path to a custom exception class, that will be
raised by ratelimit when a limit is exceeded and ``block=True``.
