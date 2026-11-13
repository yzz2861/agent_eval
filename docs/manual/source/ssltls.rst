SSL and TLS
###########

You can use SSL basic authentication with the use_ssl parameter of the Server object, you can also specify a port (636 is the default for secure ldap)::

    s = Server('servername', port = 636, use_ssl = True)  # define a secure LDAP server

To start a TLS connection on an already created _clear connection::

    c.start_tls()

Some older versions (up to 2.7.9) of the Python interpreter lack the capability to check the server certificate against
the DNS name of the server. This is a potential breach of security because a server could present a certificate issued
for another host name. ldap3 includes a backport of this capability ported from the 3.4.3 version of the Python interpreter.
If you want to keep your application up to date with the hostname checking capability of the latest Python version
you can install the backports.ssl_match_hostname package from pypi. The ldap3 library will detect and use it instead of
the included static backport.

The Tls object
==============

You can customize the server Tls object with references to keys, certificates and CAs. It includes all attributes needed to securely connect over an ssl socket:

* local_private_key_file: the file with the private key of the client
* local_certificate_file: the file with the certificate of the client
* validate: specifies if the server certificate must be validated, values can be: CERT_NONE (certificates are ignored), CERT_OPTIONAL (not required, but validated if provided) and CERT_REQUIRED (required and validated)
* version: SSL or TLS version to use, can be one of the following: SSLv2, SSLv3, SSLv23, TLSv1 (as per Python 3.3. The version list can be different in other Python versions)
* ca_certs_file: the file containing the certificates of the certification authorities
* ciphers: a string that specify which chipers must be used. It works on recent Python interpreters that allow to change the cipher in the SSLContext or in the the wrap_socket() method, it's ignored on older versions.

Tls object uses the ssl module of the Python standard library with additional checking functions that are missing from the Python 2 standard library.

The needed constants are defined in the ssl package.

Server identity verification
============================

When ``validate`` is set to ``ssl.CERT_REQUIRED`` or ``ssl.CERT_OPTIONAL`` the Tls object now verifies the
server identity by default. The checks are implemented in ldap3 itself so the same, modern rules apply on every
interpreter instead of relying on the ssl module default policy:

* the host name is normalized before being used: DNS names are lowercased and IDNA encoded (A-label), IPv4 and
  IPv6 literals are parsed with the ipaddress module and IPv6 zone identifiers (for example ``fe80::1%eth0``)
  never become part of the certificate match
* DNS names only match ``dNSName`` SAN entries, IP literals only match ``iPAddress`` SAN entries; an IP address
  is never compared with a DNS-style name
* wildcard certificates are accepted only when the wildcard is in the left-most label and matches a single
  label, so ``*.example.com`` matches ``www.example.com`` but never ``a.b.example.com``
* the subject commonName is used only when the certificate has no subjectAltName at all and the Tls object is
  explicitly created with ``allow_common_name_fallback=True``; the default is to reject certificates without SAN
* SNI uses the normalized DNS name. IP literals and hosts whose only identifier is an IP address do not send a
  DNS-style SNI

The relevant Tls parameters are:

* ``check_hostname``: enables the identity verification; defaults to True for ``CERT_REQUIRED``/``CERT_OPTIONAL``
  and False for ``CERT_NONE`` (the historical, non-verifying behavior). Setting it to True with ``CERT_NONE``
  raises a configuration error
* ``allow_common_name_fallback``: when True, permits matching the subject commonName for certificates without a
  subjectAltName. Defaults to False
* ``server_name``: the identity to verify and to use for SNI. Use it when the connected endpoint differs from
  the certified host, for example an IP address or a proxy in front of the real LDAP service. The legacy
  ``sni`` parameter keeps working and is treated as an alias
* ``valid_names``: additional accepted identities, kept for backward compatibility

Identity, certificate chain and validity period problems are reported with distinct exceptions so callers can
react differently:

* ``LDAPCertificateChainError``: untrusted/unknown CA, bad signature or other chain problems while performing
  the TLS handshake
* ``LDAPCertificateExpiredError``: the certificate is expired or not yet valid
* ``LDAPCertificateHostnameError``: the chain is valid but none of the certificate identities matches the
  verified host or address

The identity verified during a successful handshake is pinned on the connection (``connection.verified_tls_host``).
Redirecting an already verified connection to a different host through a proxy or a server pool raises
``LDAPVerifiedHostChangedError``; open a new connection (or re-run StartTLS) to verify the new endpoint.

IF you don't use a specific Tls object and set use_ssl=True in the Server definition, a default Tls object will be used, it has no certificate
files, uses the ssl.PROTOCOL_SSLv23 (if available in your Python interpreter) and performs no validation of the server certificate.
It's recommended to set validate=ssl.CERT_REQUIRED to verify the certificate server. Example::

    tls = Tls(local_private_key_file='client_private_key.pem', local_certificate_file='client_cert.pem', validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLSv1, ca_certs_file='ca_certs.b64')


SSLContext
----------
You can use SSLContext if running in Python 3.4 or newer.

The use of ssl.SSLContext make TLS operation more flexible, It integrates with the system wide Certification Authorities and also ensure that there are "reasonable" security defaults when using the TLS
layer. It's also possible to specify a file system path containing
the CA file or even pass certificate data "on the fly".

When defining the Tls object you have the following additional parameters available:

* ca_certs_file: the usual link to the certification authority chain of certificates
* ca_certs_path: a link to a path containing the certification  authorities certificates (reashed, as expected by OpenSSL)
* ca_certs_data: CA certificate data stored in memory

if you leave all these parameter to None the SSLContext will use the
system wide certificate store (ssl path on linux, CA stores on
Windows)

If the SSLContext is not available the library will fall back to the
ssl wrapped socket mechanism.


SASL
----

Three SASL mechanisms are currently implemented in the ldap3 library: EXTERNAL, DIGEST-MD5 and GSSAPI (Kerberos, via the gssapi package). Even if DIGEST-MD5 is **deprecated** and moved to historic (RFC6331, July 2011)
because it is **insecure and unsuitable for use in protocols** (as stated by the RFC) I've developed the authentication phase of the protocol because it is still used in LDAP servers.

External
^^^^^^^^

You can use the EXTERNAL mechanism when you're on a secure (TLS) channel. You can provide an authorization identity string in sasl_credentials or let the
server trust the credential provided when establishing the secure channel::

     tls = Tls(local_private_key_file = 'key.pem', local_certificate_file = 'cert.pem', validate = ssl.CERT_REQUIRED, version = ssl.PROTOCOL_TLSv1,
               ca_certs_file = 'cacert.b64')
     server = Server(host = test_server, port = test_port_ssl, use_ssl = True, tls = tls)
     connection = Connection(server, auto_bind = True, version = 3, client_strategy = test_strategy, authentication = SASL,
                             sasl_mechanism = 'EXTERNAL', sasl_credentials = 'username')

If the bind operation does not work with::

     sasl_credentials = None

you can try::

     sasl_credentials = ''

Digest-MD5
^^^^^^^^^^

To use the DIGEST-MD5 mechanism you must pass a 4-value or 5-value tuple as sasl_credentials: (realm, user, password, authz_id, enable_protection). You can pass None
for 'realm', 'authz_id' and 'enable_protection' if not used::

    from ldap3 import Server, Connection, SASL, DIGEST_MD5
    server = Server(host = test_server, port = test_port)
    c = Connection(server, auto_bind = True, version = 3, client_strategy = test_strategy, authentication = SASL,
                             sasl_mechanism = DIGEST_MD5, sasl_credentials = (None, 'username', 'password', None, ENCRYPT))

Username is not required to be an LDAP entry, but it can be any identifier recognized by the server (i.e. email, principal, ...). If
you pass None as 'realm' the default realm of the LDAP server will be used.

``enable_protection`` is an optional argument, which is only relevant for Digest-MD5 authentication. This argument enable or disable signing/encryption
(Integrity or Confidentiality protection) when performing LDAP queries.
LDAP signing is a way to prevent replay attacks without encrypting the LDAP traffic. Microsoft publicly recommend to enforce LDAP signing when talking to
an Active Directory server : https://support.microsoft.com/en-us/help/4520412/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows
LDAP encryption is a way to prevent eavesdropping, it is especially useful to send/receive sensitive data (e.g password change for a user). Active Directory supports Digest-MD5 encryption : https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a98c1f56-8246-4212-8c4e-d92da1a9563b.

* When ``enable_protection`` is set to SIGN, LDAP requests are signed and signature of LDAP responses is verified.
* When ``enable_protection`` is set to ENCRYPT, LDAP requests are encrypted and LDAP responses are decrypted and their signature is verified.
* When ``enable_protection`` is set to any other value or not set, LDAP requests are not signed.


**Using DIGEST-MD5 without LDAP signing is deprecated and should not be used.**

Using certificate authentication with Microsoft Active Directory
================================================================

Microsoft provides two ways to use certificate authentication within an Active Directory environment as described in the documentation: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8e73932f-70cf-46d6-88b1-8d9f86235e81.

If you use an implicit TLS connection (i.e., on the port 636), then the connection is considered to be immediately authenticated (bound) as 
the credentials represented by the client certificate. Thus you have to use the function ``open()`` instead of ``bind()``::

     import ldap3
     tls = ldap3.Tls(local_private_key_file='user.key',local_certificate_file='user.crt')
     ldap_server = ldap3.Server('servername', use_ssl=True, port=636, tls=tls)
     ldap_connection = ldap3.Connection(ldap_server)
     ldap_connection.open()
     print(ldap_connection.extend.standard.who_am_i())

If you use an explicit TLS connection (via StartTLS), you have to use the EXTERNAL mechanism and set the ``auto_bind`` parameter of 
the ``Connection`` object to ``AUTO_BIND_TLS_BEFORE_BIND``::

     import ldap3
     tls = ldap3.Tls(local_private_key_file='user.key',local_certificate_file='user.crt')
     ldap_server = ldap3.Server('servername', port=389, tls=tls)
     ldap_connection = ldap3.Connection(ldap_server, authentication=ldap3.SASL, sasl_mechanism=ldap3.EXTERNAL, auto_bind=ldap3.AUTO_BIND_TLS_BEFORE_BIND)
     print(ldap_connection.extend.standard.who_am_i())

According to the documentation, Active Directory also implements "explicit assertion" as defined in the RFC2830 but only when using StartTLS. 
The ``authzId`` field must contains the distinguished name of the object (prefixed with ``dn:``) associated with the credentials represented by the certificate::

    ldap_connection = ldap3.Connection(ldap_server, authentication=ldap3.SASL, sasl_mechanism=ldap3.EXTERNAL, auto_bind=ldap3.AUTO_BIND_TLS_BEFORE_BIND, 
                                        sasl_credentials='dn:CN=John Doe,CN=Users,DC=contoso,DC=com')
