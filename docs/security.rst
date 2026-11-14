.. _security-chapter:

=======================
Security considerations
=======================


.. _security-client-ip:

Client IP address
=================

IP address is an extremely common rate limit :ref:`key <keys-chapter>`,
so it is important to configure correctly, especially in the
equally-common case where Django is behind a load balancer or other
reverse proxy.

Django-Ratelimit is **not** the correct place to handle reverse proxies
and adjust the IP address, and patches dealing with it will not be
accepted. There is `too much variation`_ in the wild to handle it
safely.

This is the same reason `Django dropped`_
``SetRemoteAddrFromForwardedFor`` middleware in 1.1: no such "mechanism
can be made reliable enough for general-purpose use" and it "may lead
developers to assume that the value of ``REMOTE_ADDR`` is 'safe'."


Risks
-----

Mishandling client IP data creates an IP spoofing vector that allows
attackers to circumvent IP ratelimiting entirely. Consider an attacker
with the real IP address 3.3.3.3 that adds the following to a request::

    X-Forwarded-For: 1.2.3.4

A misconfigured web server may pass the header value along, e.g.::

    X-Forwarded-For: 3.3.3.3, 1.2.3.4

Alternatively, if the web server sends a different header, like
``X-Cluster-Client-IP`` or  ``X-Real-IP``, and passes along the
spoofed ``X-Forwarded-For`` header unchanged, a mistake in ratelimit or
a misconfiguration in Django could read the spoofed header instead of
the intended one.


Remediation
-----------

There are two options, configuring django-ratelimit or adding global
middleware. Which makes sense depends on your setup.


Middleware
^^^^^^^^^^

Writing a small middleware class to set ``REMOTE_ADDR`` to the actual
client IP address is generally simple::

    def reverse_proxy(get_response):
        def process_request(request):
            request.META['REMOTE_ADDR'] = # [...]
            return get_response(request)
        return process_request

where ``# [...]`` depends on your environment. This middleware should be
close to the top of the list::

    MIDDLEWARE = (
        'path.to.reverse_proxy',
        # ...
    )

Then the ``@ratelimit`` decorator can be used with the ``ip`` key::

    @ratelimit(key='ip', rate='10/s')

Trusted proxy headers
^^^^^^^^^^^^^^^^^^^^

When every request reaches Django through a known set of reverse proxies, the
explicit ``RATELIMIT_TRUSTED_PROXIES`` and
``RATELIMIT_CLIENT_IP_HEADER`` settings provide a safe way to read the client
IP from a proxy header without trusting arbitrary clients.

The header is only read when the immediate peer (``REMOTE_ADDR``) is part of
the trusted set. With ``X-Forwarded-For``, addresses are walked right-to-left
and trusted proxies are skipped until the first untrusted address, so an
attacker cannot rotate the leftmost value to obtain a fresh bucket. With a
single-value header such as ``X-Real-IP``, commas or a competing
``X-Forwarded-For`` header are rejected as ambiguous. Malformed or
unverifiable chains fail closed instead of selecting a spoofed bucket.

Ratelimit keys
^^^^^^^^^^^^^^

Alternatively, if the client IP address is in a simple header (i.e. a
header like ``X-Real-IP`` that *only* contains the client IP, unlike
``X-Forwarded-For`` which may contain intermediate proxies) you can use
a ``header:`` key::

    @ratelimit(key='header:x-real-ip', rate='10/s')

.. _too much variation: http://en.wikipedia.org/wiki/Talk:X-Forwarded-For#Variations
.. _Django dropped: https://docs.djangoproject.com/en/2.1/releases/1.1/#removed-setremoteaddrfromforwardedfor-middleware


.. _security-brute-force:

Brute force attacks
===================

One of the key uses of ratelimiting is preventing brute force or
dictionary attacks against login forms. These attacks generally take one
of a few forms:

- One IP address trying one username with many passwords.
- Many IP addresses trying one username with many passwords.
- One IP address trying many usernames with a few common passwords.
- Many IP addresses trying many usernames with one or a few common
  passwords.

.. note::
   Unfortunately, the fourth case of many IPs trying many usernames can
   be difficult to distinguish from regular user behavior and requires
   additional signals, such as a consistent user agent or a common
   network prefix.

Protecting against the single IP address cases is easy::

    @ratelimit(key='ip')
    def login_view(request):
        pass

Also limiting by username provides better protection::

    @ratelimit(key='ip')
    @ratelimit(key='post:username')
    def login_view(request):
        pass

**Using passwords as key values is not recommended.** Key values are
never stored in a raw form, even as cache keys, but they are constructed
with a fast hash function.


Denial of Service
-----------------

However, limiting based on field values may open a `denial of service`_
vector against your users, preventing them from logging in.

For pages like login forms, consider implementing a soft blocking
mechanism, such as requiring a captcha, rather than a hard block with a
``PermissionDenied`` error.


Network Address Translation
---------------------------

Depending on your profile of your users, you may have many users behind
NAT (e.g. users in schools or in corporate networks). It is reasonable
to set a higher limit on a per-IP limit than on a username or password
limit.

.. _denial of service: http://en.wikipedia.org/wiki/Denial-of-service_attack?oldformat=true


.. _security-user-supplied:

User-supplied Data
==================

Using data from GET (``key='get:X'``) POST (``key='post:X'``) or headers
(``key='header:x-x'``) that are provided directly by the browser or
other client presents a risk. Unless there is some requirement of the
attack that requires the client *not* change the value (for example,
attempting to brute force a password requires that the username be
consistent) clients can trivially change these values on every request.

Headers that are provided by web servers or reverse proxies should be
independently audited to ensure they cannot be affected by clients.

The ``User-Agent`` header is especially dangerous, since bad actors can
change it on every request, and many good actors may share the same
value.
