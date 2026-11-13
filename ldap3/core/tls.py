"""
"""

# Created on 2013.08.05
#
# Author: Giovanni Cannata
#
# Copyright 2013 - 2025 Giovanni Cannata
#
# This file is part of ldap3.
#
# ldap3 is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ldap3 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with ldap3 in the COPYING and COPYING.LESSER files.
# If not, see <http://www.gnu.org/licenses/>.

from .exceptions import LDAPSSLNotSupportedError, LDAPSSLConfigurationError, LDAPCertificateError, \
    start_tls_exception_factory, LDAPStartTLSError
from .exceptions import LDAPCertificateChainError, LDAPCertificateExpiredError, LDAPCertificateHostnameError
from .. import SEQUENCE_TYPES
from ..utils.host import normalize_host, match_certificate_identity
from ..utils.log import log, log_enabled, ERROR, BASIC, NETWORK

try:
    # noinspection PyUnresolvedReferences
    import ssl
except ImportError:
    if log_enabled(ERROR):
        log(ERROR, 'SSL not supported in this Python interpreter')
    raise LDAPSSLNotSupportedError('SSL not supported in this Python interpreter')

try:  # try to use SSLContext
    # noinspection PyUnresolvedReferences
    from ssl import create_default_context, Purpose  # defined in Python 3.4 and Python 2.7.9
    use_ssl_context = True
except ImportError:
    use_ssl_context = False
    if log_enabled(BASIC):
        log(BASIC, 'SSLContext unavailable')

from os import path


# OpenSSL X509 verification codes (see x509_vfy.h) relevant while
# establishing the TLS connection. Host name mismatch is checked separately.
_CERTIFICATE_EXPIRED_CODES = frozenset([10, 9, 12])  # expired, cert not yet valid, CRL validity
_CERTIFICATE_CHAIN_CODES = frozenset([
    18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
    36, 37, 38, 43, 44, 45, 50, 51, 52, 53, 54, 55, 56, 66, 67, 68, 69, 70,
    71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88,
    89, 90, 91, 92, 93, 94, 95
])


def classify_ssl_certificate_error(error):
    """Map an ssl module handshake error to a specific LDAPCertificateError
    subclass so chain, expiration and hostname problems are distinguishable.
    """
    verify_code = getattr(error, 'verify_code', None)
    message = str(error)
    if verify_code in _CERTIFICATE_EXPIRED_CODES or 'expired' in message.lower() or 'not yet valid' in message.lower():
        return LDAPCertificateExpiredError(message)
    if verify_code in _CERTIFICATE_CHAIN_CODES or 'self signed' in message.lower() or 'unable to get' in message.lower() \
            or 'unable to verify' in message.lower() or 'unknown ca' in message.lower():
        return LDAPCertificateChainError(message)
    return LDAPCertificateChainError(message)


# noinspection PyProtectedMember
class Tls(object):
    """
    tls/ssl configuration for Server object
    Starting from python 2.7.9 and python 3.4 uses the SSLContext object
    that tries to read the CAs defined at system level
    ca_certs_path and ca_certs_data are valid only when using SSLContext
    local_private_key_password is valid only when using SSLContext
    ssl_options is valid only when using SSLContext
    sni is the server name for Server Name Indication (when available)
    server_name is the identity verified against the server certificate and
    used (after normalization) as SNI; it allows verifying a host different
    from the connected endpoint (proxies, connection pools).
    check_hostname enables the certificate identity verification and is on by
    default whenever the certificate is validated.
    allow_common_name_fallback permits matching the subject commonName only
    when the certificate has no subjectAltName; it defaults to False because
    RFC 6125 deprecates the fallback.
    """

    def __init__(self,
                 local_private_key_file=None,
                 local_certificate_file=None,
                 validate=ssl.CERT_NONE,
                 version=None,
                 ssl_options=None,
                 ca_certs_file=None,
                 valid_names=None,
                 ca_certs_path=None,
                 ca_certs_data=None,
                 local_private_key_password=None,
                 ciphers=None,
                 sni=None,
                 peer_certificate=None,
                 check_hostname=None,
                 allow_common_name_fallback=False,
                 server_name=None):
        if ssl_options is None:
            ssl_options = []
        self.ssl_options = ssl_options
        if validate in [ssl.CERT_NONE, ssl.CERT_OPTIONAL, ssl.CERT_REQUIRED]:
            self.validate = validate
        elif validate:
            if log_enabled(ERROR):
                log(ERROR, 'invalid validate parameter <%s>', validate)
            raise LDAPSSLConfigurationError('invalid validate parameter')
        if ca_certs_file and path.exists(ca_certs_file):
            self.ca_certs_file = ca_certs_file
        elif ca_certs_file:
            if log_enabled(ERROR):
                log(ERROR, 'invalid CA public key file <%s>', ca_certs_file)
            raise LDAPSSLConfigurationError('invalid CA public key file')
        else:
            self.ca_certs_file = None

        if ca_certs_path and use_ssl_context and path.exists(ca_certs_path):
            self.ca_certs_path = ca_certs_path
        elif ca_certs_path and not use_ssl_context:
            if log_enabled(ERROR):
                log(ERROR, 'cannot use CA public keys path, SSLContext not available')
            raise LDAPSSLNotSupportedError('cannot use CA public keys path, SSLContext not available')
        elif ca_certs_path:
            if log_enabled(ERROR):
                log(ERROR, 'invalid CA public keys path <%s>', ca_certs_path)
            raise LDAPSSLConfigurationError('invalid CA public keys path')
        else:
            self.ca_certs_path = None

        if ca_certs_data and use_ssl_context:
            self.ca_certs_data = ca_certs_data
        elif ca_certs_data:
            if log_enabled(ERROR):
                log(ERROR, 'cannot use CA data, SSLContext not available')
            raise LDAPSSLNotSupportedError('cannot use CA data, SSLContext not available')
        else:
            self.ca_certs_data = None

        if local_private_key_password and use_ssl_context:
            self.private_key_password = local_private_key_password
        elif local_private_key_password:
            if log_enabled(ERROR):
                log(ERROR, 'cannot use local private key password, SSLContext not available')
            raise LDAPSSLNotSupportedError('cannot use local private key password, SSLContext is not available')
        else:
            self.private_key_password = None

        self.version = version
        self.private_key_file = local_private_key_file
        self.certificate_file = local_certificate_file
        self.valid_names = valid_names
        self.ciphers = ciphers
        # ``sni`` is kept for backward compatibility. ``server_name`` is the
        # preferred name because it drives both SNI and identity verification.
        explicit_name = server_name if server_name is not None else sni
        self.server_name = explicit_name
        self.sni = explicit_name

        if not isinstance(allow_common_name_fallback, bool):
            raise LDAPSSLConfigurationError('allow_common_name_fallback must be a boolean')
        self.allow_common_name_fallback = allow_common_name_fallback

        # check_hostname defaults to True as soon as a certificate is
        # requested; CERT_NONE keeps the historical "no verification" behavior.
        if check_hostname is None:
            check_hostname = validate in (ssl.CERT_REQUIRED, ssl.CERT_OPTIONAL)
        if not isinstance(check_hostname, bool):
            raise LDAPSSLConfigurationError('check_hostname must be a boolean')
        if check_hostname and validate == ssl.CERT_NONE:
            raise LDAPSSLConfigurationError('check_hostname requires validate to be CERT_OPTIONAL or CERT_REQUIRED')
        self.check_hostname_enabled = check_hostname

        # the identity actually verified during the most recent handshake
        self.verified_host = None
        self.peer_identity = None

        if log_enabled(BASIC):
            log(BASIC, 'instantiated Tls: <%r>' % self)

    def __str__(self):
        s = [
            'protocol: ' + str(self.version),
            'client private key: ' + ('present ' if self.private_key_file else 'not present'),
            'client certificate: ' + ('present ' if self.certificate_file else 'not present'),
            'private key password: ' + ('present ' if self.private_key_password else 'not present'),
            'CA certificates file: ' + ('present ' if self.ca_certs_file else 'not present'),
            'CA certificates path: ' + ('present ' if self.ca_certs_path else 'not present'),
            'CA certificates data: ' + ('present ' if self.ca_certs_data else 'not present'),
            'verify mode: ' + str(self.validate),
            'valid names: ' + str(self.valid_names),
            'ciphers: ' + str(self.ciphers),
            'sni: ' + str(self.sni),
            'server name: ' + str(self.server_name),
            'check hostname: ' + str(self.check_hostname_enabled),
            'commonName fallback: ' + str(self.allow_common_name_fallback)
        ]
        return ' - '.join(s)

    def __repr__(self):
        r = '' if self.private_key_file is None else ', local_private_key_file={0.private_key_file!r}'.format(self)
        r += '' if self.certificate_file is None else ', local_certificate_file={0.certificate_file!r}'.format(self)
        r += '' if self.validate is None else ', validate={0.validate!r}'.format(self)
        r += '' if self.version is None else ', version={0.version!r}'.format(self)
        r += '' if self.ca_certs_file is None else ', ca_certs_file={0.ca_certs_file!r}'.format(self)
        r += '' if self.ca_certs_path is None else ', ca_certs_path={0.ca_certs_path!r}'.format(self)
        r += '' if self.ca_certs_data is None else ', ca_certs_data={0.ca_certs_data!r}'.format(self)
        r += '' if self.ciphers is None else ', ciphers={0.ciphers!r}'.format(self)
        r += '' if self.sni is None else ', sni={0.sni!r}'.format(self)
        r += ', check_hostname={0.check_hostname_enabled!r}'.format(self)
        r += ', allow_common_name_fallback={0.allow_common_name_fallback!r}'.format(self)
        r += '' if self.server_name is None else ', server_name={0.server_name!r}'.format(self)
        r = 'Tls(' + r[2:] + ')' 
        return r

    def wrap_socket(self, connection, do_handshake=False):
        """
        Adds TLS to the connection socket
        """
        # Resolve and pin the identity to verify before touching the socket.
        # Using a snapshot makes proxy / connection-pool code safe: changing
        # connection.server.host afterwards cannot alter what was verified.
        verify_target = self._resolve_verify_target(connection)
        sni_name = None
        if verify_target is not None:
            sni_name = verify_target.sni_value

        if use_ssl_context:
            if self.version is None:  # uses the default ssl context for reasonable security
                ssl_context = create_default_context(purpose=Purpose.SERVER_AUTH,
                                                     cafile=self.ca_certs_file,
                                                     capath=self.ca_certs_path,
                                                     cadata=self.ca_certs_data)
            else:  # code from create_default_context in the Python standard library 3.5.1, creates a ssl context with the specificd protocol version
                ssl_context = ssl.SSLContext(self.version)
                if self.ca_certs_file or self.ca_certs_path or self.ca_certs_data:
                    ssl_context.load_verify_locations(self.ca_certs_file, self.ca_certs_path, self.ca_certs_data)
                elif self.validate != ssl.CERT_NONE:
                    ssl_context.load_default_certs(Purpose.SERVER_AUTH)

            if self.ciphers:
                try:
                    ssl_context.set_ciphers(self.ciphers)
                except ssl.SSLError:
                    pass

            if self.certificate_file:
                ssl_context.load_cert_chain(self.certificate_file, keyfile=self.private_key_file, password=self.private_key_password)
            # Chain/expiration verification is handled by OpenSSL; identity
            # (DNS/IP SAN, IDNA, wildcards) is verified explicitly below so
            # the behavior is identical across Python versions.
            ssl_context.check_hostname = False
            ssl_context.verify_mode = self.validate
            for option in self.ssl_options:
                ssl_context.options |= option

            try:
                if sni_name:
                    wrapped_socket = ssl_context.wrap_socket(connection.socket, server_side=False, do_handshake_on_connect=do_handshake, server_hostname=sni_name)
                else:
                    wrapped_socket = ssl_context.wrap_socket(connection.socket, server_side=False, do_handshake_on_connect=do_handshake)
            except ssl.SSLError as error:
                raise self._classify_handshake_error(error)
            if log_enabled(NETWORK):
                log(NETWORK, 'socket wrapped with SSL using SSLContext for <%s>', connection)
        else:
            if self.version is None and hasattr(ssl, 'PROTOCOL_SSLv23'):
                self.version = ssl.PROTOCOL_SSLv23
            if self.ciphers:
                try:

                    wrapped_socket = ssl.wrap_socket(connection.socket,
                                                     keyfile=self.private_key_file,
                                                     certfile=self.certificate_file,
                                                     server_side=False,
                                                     cert_reqs=self.validate,
                                                     ssl_version=self.version,
                                                     ca_certs=self.ca_certs_file,
                                                     do_handshake_on_connect=do_handshake,
                                                     ciphers=self.ciphers)
                except ssl.SSLError as error:
                    raise self._classify_handshake_error(error)
                except TypeError:  # in python2.6 no ciphers argument is present, failback to self.ciphers=None
                    self.ciphers = None

            if not self.ciphers:
                try:
                    wrapped_socket = ssl.wrap_socket(connection.socket,
                                                     keyfile=self.private_key_file,
                                                     certfile=self.certificate_file,
                                                     server_side=False,
                                                     cert_reqs=self.validate,
                                                     ssl_version=self.version,
                                                     ca_certs=self.ca_certs_file,
                                                     do_handshake_on_connect=do_handshake)
                except ssl.SSLError as error:
                    raise self._classify_handshake_error(error)
            if log_enabled(NETWORK):
                log(NETWORK, 'socket wrapped with SSL for <%s>', connection)

        if do_handshake and (self.validate == ssl.CERT_REQUIRED or self.validate == ssl.CERT_OPTIONAL):
            self._verify_peer_identity(wrapped_socket, verify_target)

        self.peer_certificate = wrapped_socket.getpeercert(binary_form=True)
        self.verified_host = verify_target.match_value if verify_target is not None else None
        self._pin_connection_identity(connection, verify_target)
        connection.socket = wrapped_socket
        return

    def _resolve_verify_target(self, connection):
        """Return the normalized host that must be verified for this socket."""
        if not self.check_hostname_enabled:
            return None

        candidate_names = []
        if self.server_name is not None:
            candidate_names.append(self.server_name)
        elif connection.server is not None:
            candidate_names.append(connection.server.host)
        if self.valid_names:
            if isinstance(self.valid_names, SEQUENCE_TYPES):
                candidate_names.extend(self.valid_names)
            else:
                candidate_names.append(self.valid_names)

        for candidate in candidate_names:
            if not candidate:
                continue
            try:
                return normalize_host(candidate)
            except ValueError:
                if log_enabled(ERROR):
                    log(ERROR, 'unable to normalize host name <%s>', candidate)

        raise LDAPSSLConfigurationError('no valid host name available for TLS identity verification')

    @staticmethod
    def _classify_handshake_error(error):
        """Convert an OpenSSL handshake failure into the proper certificate
        error category while keeping non-verification SSL errors untouched."""
        if isinstance(error, ssl.SSLError) and getattr(error, 'verify_code', None) is not None:
            classified = classify_ssl_certificate_error(error)
            return type(classified)(str(error))
        return error

    def _pin_connection_identity(self, connection, verify_target):
        """Record the verified identity on the connection so later code can
        detect that the underlying Server object was swapped after the
        handshake."""
        if verify_target is None:
            connection.verified_tls_host = None
            connection.verified_tls_server = None
            return
        connection.verified_tls_host = verify_target.match_value
        connection.verified_tls_server = connection.server

    def _verify_peer_identity(self, wrapped_socket, verify_target):
        if verify_target is None:
            return

        peer_cert = wrapped_socket.getpeercert()
        if not peer_cert:
            # CERT_OPTIONAL with no presented certificate: nothing to verify.
            if log_enabled(NETWORK):
                log(NETWORK, 'no peer certificate presented, identity verification skipped for <%s>',
                    verify_target.match_value)
            return

        candidate_names = [verify_target]
        if self.valid_names:
            extra_names = self.valid_names if isinstance(self.valid_names, SEQUENCE_TYPES) else [self.valid_names]
            for extra_name in extra_names:
                if not extra_name:
                    continue
                try:
                    candidate_names.append(normalize_host(extra_name))
                except ValueError:
                    if log_enabled(ERROR):
                        log(ERROR, 'invalid additional valid name <%s>', extra_name)

        errors = []
        for candidate in candidate_names:
            try:
                identity_type, identity_value = match_certificate_identity(
                    peer_cert, candidate, self.allow_common_name_fallback)
                self.peer_identity = (identity_type, identity_value, candidate.match_value)
                if log_enabled(NETWORK):
                    log(NETWORK, 'certificate %s %r matches verified host <%s>',
                        identity_type, identity_value, candidate.match_value)
                return
            except ValueError as error:
                errors.append(str(error))

        message = 'TLS hostname verification failed for %r: %s' % (
            verify_target.match_value, '; '.join(errors))
        if log_enabled(ERROR):
            log(ERROR, message)
        raise LDAPCertificateHostnameError(message)

    def start_tls(self, connection):
        if connection.server.ssl:  # ssl already established at server level
            return False

        if (connection.tls_started and not connection._executing_deferred) or connection.strategy._outstanding or connection.sasl_in_progress:
            # Per RFC 4513 (3.1.1)
            if log_enabled(ERROR):
                log(ERROR, "can't start tls because operations are in progress for <%s>", self)
            return False
        connection.starting_tls = True
        if log_enabled(BASIC):
            log(BASIC, 'starting tls for <%s>', connection)
        if not connection.strategy.sync:
            connection._awaiting_for_async_start_tls = True  # some flaky servers (OpenLDAP) doesn't return the extended response name in response
        result = connection.extended('1.3.6.1.4.1.1466.20037')
        if not connection.strategy.sync:
            # asynchronous - _start_tls must be executed by the strategy
            response = connection.get_response(result)
            if response != (None, None):
                if log_enabled(BASIC):
                    log(BASIC, 'tls started for <%s>', connection)
                return True
            else:
                if log_enabled(BASIC):
                    log(BASIC, 'tls not started for <%s>', connection)
                return False
        else:
            if connection.result['description'] not in ['success']:
                # startTLS failed
                connection.last_error = 'startTLS failed - ' + str(connection.result['description'])
                if log_enabled(ERROR):
                    log(ERROR, '%s for <%s>', connection.last_error, connection)
                raise LDAPStartTLSError(connection.last_error)
            if log_enabled(BASIC):
                log(BASIC, 'tls started for <%s>', connection)
            return self._start_tls(connection)

    def _start_tls(self, connection):
        try:
            self.wrap_socket(connection, do_handshake=True)
        except Exception as e:
            connection.last_error = 'wrap socket error: ' + str(e)
            if log_enabled(ERROR):
                log(ERROR, 'error <%s> wrapping socket for TLS in <%s>', connection.last_error, connection)
            if isinstance(e, LDAPCertificateError):
                raise
            raise start_tls_exception_factory(e)(connection.last_error)
        finally:
            connection.starting_tls = False

        if connection.usage:
            connection._usage.wrapped_sockets += 1
        connection.tls_started = True
        return True


def check_hostname(sock, server_name, additional_names):
    """Backward-compatible module level helper kept for external callers.

    It uses the same strict identity logic as :meth:`Tls.wrap_socket`.
    """
    server_certificate = sock.getpeercert()
    if log_enabled(NETWORK):
        log(NETWORK, 'certificate found for %s: %s', sock, server_certificate)
    host_names = [server_name]
    if additional_names:
        if isinstance(additional_names, SEQUENCE_TYPES):
            host_names.extend(additional_names)
        else:
            host_names.append(additional_names)

    errors = []
    for host_name in host_names:
        if not host_name:
            continue
        try:
            normalized = normalize_host(host_name)
            match_certificate_identity(server_certificate, normalized)
            if log_enabled(NETWORK):
                log(NETWORK, 'certificate matches host name <%s>', host_name)
            return
        except ValueError as error:
            errors.append(str(error))
            if log_enabled(NETWORK):
                log(NETWORK, str(error))

    if log_enabled(ERROR):
        log(ERROR, "hostname doesn't match certificate")
    raise LDAPCertificateHostnameError("certificate %s doesn't match any name in %s: %s"
                                       % (server_certificate, str(host_names), '; '.join(errors)))
