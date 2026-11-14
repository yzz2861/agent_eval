# Copyright (c) 2015-2024 by Ron Frederick <ronf@timeheart.net> and others.
#
# This program and the accompanying materials are made available under
# the terms of the Eclipse Public License v2.0 which accompanies this
# distribution and is available at:
#
#     http://www.eclipse.org/legal/epl-2.0/
#
# This program may also be made available under the following secondary
# licenses when the conditions for such availability set forth in the
# Eclipse Public License v2.0 are satisfied:
#
#    GNU General Public License, Version 2.0, or any later versions of
#    that license
#
# SPDX-License-Identifier: EPL-2.0 OR GPL-2.0-or-later
#
# Contributors:
#     Ron Frederick - initial implementation, API, and documentation
#     Alexander Travov - proposed changes to add negated patterns, hashed
#                        entries, and support for the revoked marker
#     Josh Yudaken - proposed change to split parsing and matching to avoid
#                    parsing large known_hosts lists multiple times

"""Parser for SSH known_hosts files"""

import binascii
from hashlib import sha1
import hmac
from typing import Callable, Dict, List, Optional
from typing import Sequence, Tuple, Union, cast

try:
    from .crypto import X509NamePattern
    _x509_available = True
except ImportError: # pragma: no cover
    _x509_available = False

from .misc import IPAddress, ip_address, read_file
from .pattern import HostPatternList
from .public_key import KeyImportError
from .public_key import SSHKey, SSHCertificate, SSHX509Certificate
from .public_key import import_public_key, import_certificate
from .public_key import import_certificate_subject
from .public_key import load_public_keys, load_certificates


_HostEntry = Tuple[Optional[str], Optional[SSHKey],
                   Optional[SSHX509Certificate], Optional['X509NamePattern']]

_KnownHostsKeys = Sequence[SSHKey]
_KnownHostsCerts = Sequence[SSHX509Certificate]
_KnownHostsNames = Sequence['X509NamePattern']
_KnownHostsResult = Tuple[_KnownHostsKeys, _KnownHostsKeys, _KnownHostsKeys,
                          _KnownHostsCerts, _KnownHostsCerts,
                          _KnownHostsNames, _KnownHostsNames]

_KnownHostsCallable = Callable[[str, str, Optional[int]], Sequence[str]]
_KnownHostsListArg = Union[str, Sequence[str], 'X509NamePattern']
KnownHostsArg = Union[None, str, bytes, _KnownHostsCallable, 'SSHKnownHosts',
                      _KnownHostsResult, Sequence[_KnownHostsListArg]]

# Host key conflict policies:
#
#   error:  Raise an error when conflicting host keys are found (default)
#   first:  Trust only the first key found for each host key algorithm
#   accept: Trust all matching host keys (legacy behavior)

_CONFLICT_POLICIES = ('error', 'first', 'accept')


def _load_subject_names(names: Sequence[str]) -> Sequence['X509NamePattern']:
    """Load a list of X.509 subject name patterns"""

    if not _x509_available: # pragma: no cover
        return []

    return list(map(X509NamePattern, names))


def _normalize_host(host: str) -> str:
    """Normalize a host name or IP address for known_hosts matching

       Host names are case-insensitive and a trailing dot indicating
       the DNS root is ignored. IPv6 addresses may optionally be
       enclosed in square brackets, and all IP addresses are converted
       to a canonical form so that different representations of the
       same address produce the same result.

    """

    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]

    host = host.lower()

    if host.endswith('.'):
        host = host[:-1]

    try:
        return str(ip_address(host))
    except ValueError:
        return host


def _parse_host_port(pattern: str) -> Tuple[str, Optional[int]]:
    """Split a [host]:port pattern into a host and optional port"""

    if pattern.startswith('['):
        host, sep, port = pattern[1:].partition(']:')

        if sep:
            try:
                return host, int(port)
            except ValueError:
                pass

    return pattern, None


class _PlainHost:
    """A plain host entry in a known_hosts file"""

    def __init__(self, pattern: str):
        self._pattern = HostPatternList(pattern.lower())

    def matches(self, host: str, addr: str,
                ip: Optional[IPAddress]) -> bool:
        """Return whether a host or address matches this host pattern list"""

        return self._pattern.matches(host, addr, ip)


class _HashedHost:
    """A hashed host entry in a known_hosts file"""

    _HMAC_SHA1_MAGIC = '1'

    def __init__(self, pattern: str):
        try:
            magic, salt, hosthash = pattern[1:].split('|')
            self._salt = binascii.a2b_base64(salt)
            self._hosthash = binascii.a2b_base64(hosthash)
        except (ValueError, binascii.Error):
            raise ValueError(
                f'Invalid known hosts hash entry: {pattern}') from None

        if magic != self._HMAC_SHA1_MAGIC:
            # Only support HMAC SHA-1 for now
            raise ValueError(
                f'Invalid known hosts hash type: {magic}') from None

    def matches(self, value: str) -> bool:
        """Return whether this host hash matches a value"""

        hosthash = hmac.new(self._salt, value.encode(), sha1).digest()
        return hosthash == self._hosthash


class SSHKnownHosts:
    """An SSH known hosts list

       Host names, IP addresses, and ports are normalized before
       matching, so equivalent entries written with different case,
       trailing dots, or IPv6 bracket notation are treated identically.

       Matches are performed in the following priority order:

       1. Exact entries matching the host key alias, if one is set
       2. Exact entries matching the host name
       3. Exact entries matching the IP address
       4. Hashed host entries
       5. Wildcard and CIDR pattern entries

       When multiple conflicting host keys match (different keys for
       the same host key algorithm), the conflict_policy argument
       controls whether an error is raised ('error'), only the first
       key found for each algorithm is trusted ('first'), or all
       matching keys are trusted ('accept').

    """

    def __init__(self, known_hosts: Optional[str] = None,
                 conflict_policy: str = 'error'):
        if conflict_policy not in _CONFLICT_POLICIES:
            raise ValueError(
                f'Invalid known hosts conflict policy: {conflict_policy}')

        self._conflict_policy = conflict_policy

        self._exact_entries: Dict[str, List[Tuple[Optional[int],
                                                  _HostEntry]]] = {}
        self._hashed_entries: List[Tuple['_HashedHost', _HostEntry]] = []
        self._pattern_entries: List[Tuple['_PlainHost', _HostEntry]] = []

        if known_hosts:
            self.load(known_hosts)

    def load(self, known_hosts: str) -> None:
        """Load known hosts data into this object"""

        for line in known_hosts.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            marker: Optional[str]

            try:
                if line.startswith('@'):
                    marker, pattern, data = line[1:].split(None, 2)
                else:
                    marker = None
                    pattern, data = line.split(None, 1)
            except ValueError:
                raise ValueError(
                    f'Invalid known hosts entry: {line}') from None

            if marker not in (None, 'cert-authority', 'revoked'):
                raise ValueError(
                    f'Invalid known hosts marker: {marker}') from None

            key: Optional[SSHKey] = None
            cert: Optional[SSHCertificate] = None
            subject: Optional['X509NamePattern'] = None

            try:
                key = import_public_key(data)
            except KeyImportError:
                try:
                    cert = import_certificate(data)
                except KeyImportError:
                    if not _x509_available: # pragma: no cover
                        continue

                    try:
                        subject_text = import_certificate_subject(data)
                    except KeyImportError:
                        # Ignore keys in the file that we're unable to parse
                        continue

                    subject = X509NamePattern(subject_text)

            entry = (marker, key, cast(SSHX509Certificate, cert), subject)

            if any(c in pattern for c in '*?|/!'):
                self._add_pattern(pattern, entry)
            else:
                self._add_exact(pattern, entry)

    def _add_exact(self, pattern: str, entry: _HostEntry) -> None:
        """Add an exact match entry"""

        for host_pat in pattern.split(','):
            host, port = _parse_host_port(host_pat)
            host = _normalize_host(host)

            if host not in self._exact_entries:
                self._exact_entries[host] = []

            self._exact_entries[host].append((port, entry))

    def _add_pattern(self, pattern: str, entry: _HostEntry) -> None:
        """Add a pattern match entry"""

        if pattern.startswith('|'):
            self._hashed_entries.append((_HashedHost(pattern), entry))
        else:
            self._pattern_entries.append((_PlainHost(pattern), entry))

    def _match(self, host: str, addr: str, port: Optional[int] = None,
               host_key_alias: Optional[str] = None) -> _KnownHostsResult:
        """Find host keys matching specified host, address, and port"""

        # A host key alias takes precedence over the configured host name
        host = _normalize_host(host_key_alias or host)
        addr = _normalize_host(addr) if addr else ''

        try:
            ip: Optional[IPAddress] = ip_address(addr or host)
        except ValueError:
            ip = None

        names = [host] if host else []

        if addr and addr != host:
            names.append(addr)

        # Hashed entries are matched against both the plain host/address
        # and the [host]:port form used for non-default ports
        hashed_names = list(names)

        if port:
            hashed_names += [f'[{name}]:{port}' for name in names]

        matches: List[_HostEntry] = []

        # Exact host entries take priority over hashed and pattern entries
        for name in names:
            for entry_port, entry in self._exact_entries.get(name, ()):
                if entry_port is None or entry_port == port:
                    matches.append(entry)

        # Hashed entries take priority over plain pattern entries
        for hashed, entry in self._hashed_entries:
            if any(map(hashed.matches, hashed_names)):
                matches.append(entry)

        for pattern, entry in self._pattern_entries:
            if pattern.matches(host, addr, ip):
                matches.append(entry)
            elif port:
                pattern_host = f'[{host}]:{port}' if host else ''
                pattern_addr = f'[{addr}]:{port}' if addr else ''

                if pattern.matches(pattern_host, pattern_addr, None):
                    matches.append(entry)

        host_keys: List[SSHKey] = []
        ca_keys: List[SSHKey] = []
        revoked_keys: List[SSHKey] = []
        x509_certs: List[SSHX509Certificate] = []
        revoked_certs: List[SSHX509Certificate] = []
        x509_subjects: List['X509NamePattern'] = []
        revoked_subjects: List['X509NamePattern'] = []

        for marker, key, cert, subject in matches:
            if key:
                if marker == 'revoked':
                    revoked_keys.append(key)
                elif marker == 'cert-authority':
                    ca_keys.append(key)
                else:
                    host_keys.append(key)
            elif cert:
                if marker == 'revoked':
                    revoked_certs.append(cert)
                else:
                    x509_certs.append(cert)
            else:
                assert subject is not None

                if marker == 'revoked':
                    revoked_subjects.append(subject)
                else:
                    x509_subjects.append(subject)

        host_keys = self._apply_conflict_policy(host_keys)

        return (host_keys, ca_keys, revoked_keys, x509_certs, revoked_certs,
                x509_subjects, revoked_subjects)

    def _apply_conflict_policy(self, host_keys: List[SSHKey]) -> List[SSHKey]:
        """Apply the configured policy to conflicting host keys"""

        if self._conflict_policy == 'accept':
            return host_keys

        result = []
        keys_by_alg: Dict[bytes, SSHKey] = {}

        for key in host_keys:
            prev_key = keys_by_alg.get(key.algorithm)

            if prev_key is None:
                keys_by_alg[key.algorithm] = key
                result.append(key)
            elif prev_key.public_data != key.public_data:
                if self._conflict_policy == 'error':
                    raise ValueError('Conflicting host keys with algorithm '
                                     f'{key.get_algorithm()} in known hosts')

                # The 'first' policy keeps only the first key per algorithm

        return result

    def match(self, host: str, addr: str, port: Optional[int] = None,
              host_key_alias: Optional[str] = None) -> _KnownHostsResult:
        """Match a host, IP address, and port against known_hosts patterns

           Host names and IP addresses are normalized before matching,
           so differences in case, trailing dots, and IPv6 bracket
           notation don't affect the result. If a host key alias is
           provided, it takes precedence over the host name when
           looking up exact and hashed entries.

           Entries without a port match connections on any port, while
           entries of the form [host]:port only match connections on
           that specific port.

           :param host:
               The hostname of the target host
           :param addr:
               The IP address of the target host
           :param port:
               The port number on the target host, or `None` for the default
           :param host_key_alias:
               An optional alias to look up instead of the host name
           :type host: `str`
           :type addr: `str`
           :type port: `int`
           :type host_key_alias: `str`


           :returns: A tuple of matching host keys, CA keys, and revoked keys

        """

        return self._match(host, addr, port, host_key_alias)


def import_known_hosts(data: str, conflict_policy: str = 'error'
                       ) -> SSHKnownHosts:
    """Import SSH known hosts

       This function imports known host patterns and keys in
       OpenSSH known hosts format.

       :param data:
           The known hosts data to import
       :param conflict_policy:
           The policy to apply when conflicting host keys match:
           `'error'` to raise an error, `'first'` to trust only the
           first key found for each algorithm, or `'accept'` to trust
           all matching keys
       :type data: `str`
       :type conflict_policy: `str`

       :returns: An :class:`SSHKnownHosts` object

    """

    return SSHKnownHosts(data, conflict_policy)


def read_known_hosts(filelist: Union[str, Sequence[str]],
                     conflict_policy: str = 'error') -> SSHKnownHosts:
    """Read SSH known hosts from a file or list of files

       This function reads known host patterns and keys in
       OpenSSH known hosts format from a file or list of files.

       :param filelist:
           The file or list of files to read the known hosts from
       :param conflict_policy:
           The policy to apply when conflicting host keys match:
           `'error'` to raise an error, `'first'` to trust only the
           first key found for each algorithm, or `'accept'` to trust
           all matching keys
       :type filelist: `str` or `list` of `str`
       :type conflict_policy: `str`

       :returns: An :class:`SSHKnownHosts` object

    """

    known_hosts = SSHKnownHosts(conflict_policy=conflict_policy)

    if isinstance(filelist, str):
        filelist = [filelist]

    for filename in filelist:
        known_hosts.load(read_file(filename, 'r'))

    return known_hosts


def match_known_hosts(known_hosts: KnownHostsArg, host: str,
                      addr: str, port: Optional[int],
                      host_key_alias: Optional[str] = None
                      ) -> _KnownHostsResult:
    """Match a host, IP address, and port against a known_hosts list

       This function looks up a host, IP address, and port in a list of
       host patterns in OpenSSH `known_hosts` format and returns the
       host keys, CA keys, and revoked keys which match.

       The `known_hosts` argument can be any of the following:

           * a string containing the filename to load host patterns from
           * a byte string containing host pattern data to load
           * an already loaded :class:`SSHKnownHosts` object containing
             host patterns to match against
           * an alternate matching function which accepts a host, address,
             and port and returns lists of trusted host keys, trusted CA
             keys, and revoked keys to load
           * lists of trusted host keys, trusted CA keys, and revoked keys
             to load without doing any matching

       Host names and IP addresses are normalized before matching, so
       differences in case, trailing dots, and IPv6 bracket notation
       don't affect the result. If a host key alias is provided, it
       takes precedence over the host name when looking up exact and
       hashed entries.

       :param known_hosts:
           The host patterns to match against
       :param host:
           The hostname of the target host
       :param addr:
           The IP address of the target host
       :param port:
           The port number on the target host, or `None` for the default
       :param host_key_alias:
           An optional alias to look up instead of the host name
       :type host: `str`
       :type addr: `str`
       :type port: `int`
       :type host_key_alias: `str`

       :returns: A tuple of matching host keys, CA keys, and revoked keys

    """

    if isinstance(known_hosts, str) or \
            (known_hosts and isinstance(known_hosts, list) and
             isinstance(known_hosts[0], str)):
        known_hosts = read_known_hosts(known_hosts)
    elif isinstance(known_hosts, bytes):
        known_hosts = import_known_hosts(known_hosts.decode())

    if isinstance(known_hosts, SSHKnownHosts):
        known_hosts = known_hosts.match(host, addr, port, host_key_alias)
    else:
        if callable(known_hosts):
            known_hosts = known_hosts(host, addr, port)

        result = cast(Sequence[str], known_hosts)

        result = (tuple(map(load_public_keys, result[:3])) +
                  tuple(map(load_certificates, result[3:5])) +
                  tuple(map(_load_subject_names, result[5:7])))

        if len(result) == 3:
            # Provide backward compatibility for pre-X.509 releases
            result += ((), (), (), ())

        known_hosts = cast(_KnownHostsResult, result)

    for cert in list(known_hosts[3]) + list(known_hosts[4]):
        if not cert.is_x509:
            raise ValueError('OpenSSH certificates not '
                             'allowed in known hosts') from None

    return known_hosts
