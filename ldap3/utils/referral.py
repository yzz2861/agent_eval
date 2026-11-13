"""
"""

# Created on 2026.11.14
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

"""
Trust policy helpers for automatic referral following.

A referral target is identified by its *origin*: the (ssl, host, port)
triple. Hosts are compared as DNS names only - they are never resolved
to IP addresses - so two different DNS names that happen to resolve to
the same address are still considered different targets, and a bare IP
literal is never considered equal to a DNS name.

Trust rules, in order:
  1. same-origin targets (same scheme security, same normalized host,
     same effective port) are always allowed and may reuse the current
     connection credentials;
  2. targets explicitly listed in the server "allowed_referral_hosts"
     whitelist are allowed; the current credentials are forwarded only
     when the whitelist entry allows authentication AND the hop is not
     a security downgrade (ldaps/StartTLS -> plain ldap);
  3. everything else is rejected: the referral is not followed and the
     current credentials are never sent to the untrusted target.
"""

DEFAULT_MAX_REFERRAL_DEPTH = 5
DEFAULT_MAX_REFERRAL_TIME = 60.0  # seconds, total budget for a referral chain


def normalize_referral_host(host):
    """Normalize a host name for comparison. Never resolves to an IP address."""
    if host is None:
        return ''
    return host.strip().rstrip('.').lower()


def referral_origin(ssl, host, port):
    """Return the normalized (ssl, host, port) identity of a referral target."""
    if port is None:
        port = 636 if ssl else 389
    return (True if ssl else False, normalize_referral_host(host), int(port))


def connection_origin(connection):
    """Return the normalized origin of the server a connection is bound to."""
    server = connection.server
    return referral_origin(server.ssl, server.host, server.port)


def referral_target_key(origin, base):
    """Return the identity of a referral hop for loop/duplicate detection.
    The base dn is part of the identity: a referral back to the same origin
    AND the same base is a loop, while the same origin serving a different
    base is a legitimate target."""
    return origin + ((base or '').strip().lower(),)


def parse_referral_host_spec(spec):
    """
    Parse a whitelist host specification. Accepted forms:
      '*'                       - any origin
      'host'                    - any port/scheme of host
      'host:port'               - any scheme of host on port
      'ldap://host:port'        - exact origin (plain ldap)
      'ldaps://host:port'       - exact origin (ldap over ssl)
    Return a (ssl, host, port) tuple where ssl/port may be None (wildcard).
    """
    if spec == '*':
        return None, '*', None
    ssl = None
    remain = spec
    if '://' in spec:
        scheme, _, remain = spec.partition('://')
        if scheme == 'ldaps':
            ssl = True
        elif scheme == 'ldap':
            ssl = False
        else:
            return None, None, None  # unknown scheme, never matches
    host, sep, port = remain.partition(':')
    if sep:
        if not port.isdigit() or not (0 < int(port) < 65536):
            return None, None, None  # malformed spec, never matches
        port = int(port)
    else:
        port = None
    host = normalize_referral_host(host)
    if not host:
        return None, None, None
    return ssl, host, port


def referral_host_spec_matches(spec, origin):
    """Check if a whitelist host specification matches a normalized origin."""
    spec_ssl, spec_host, spec_port = parse_referral_host_spec(spec)
    if spec_host is None:
        return False
    if spec_host == '*':
        return True
    ssl, host, port = origin
    if host != spec_host:
        return False
    if spec_port is not None and port != spec_port:
        return False
    if spec_ssl is not None and ssl != spec_ssl:
        return False
    return True


def evaluate_referral_trust(connection, origin):
    """
    Evaluate the trust policy for a normalized referral target origin.

    Return a (allowed, forward_credentials, reason) tuple:
      allowed             - the referral may be followed
      forward_credentials - the current connection credentials may be sent
                            to the target; when False only an anonymous
                            bind is performed
      reason              - human readable explanation for logging/errors
    """
    current_origin = connection_origin(connection)
    if origin == current_origin:
        return True, True, 'same origin as current connection'

    for allowed_host in connection.server.allowed_referral_hosts:
        if not isinstance(allowed_host, tuple) or len(allowed_host) != 2:
            continue
        spec, auth_allowed = allowed_host
        if referral_host_spec_matches(spec, origin):
            target_ssl = origin[0]
            current_secure = current_origin[0] or connection.tls_started
            if current_secure and not target_ssl:
                # security downgrade (ldaps/StartTLS -> plain ldap): never
                # forward credentials, even if the whitelist allows it
                return True, False, 'whitelisted target but scheme downgrade, credentials not forwarded'
            return True, bool(auth_allowed), 'whitelisted target'

    return False, False, 'referral target not in trusted scope'
