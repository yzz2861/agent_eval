# Copyright (c) 2015-2026 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Parser for SSH authorized_keys files"""

from pathlib import PurePath
from typing import Dict, List, Mapping, Optional, Sequence
from typing import Set, Tuple, Union, cast

try:
    # pylint: disable=unused-import
    from .crypto import X509Name, X509NamePattern
    _x509_available = True
except ImportError: # pragma: no cover
    _x509_available = False

from .logging import logger
from .misc import FilePath, IPAddress, OptionsParser, ip_address, read_file
from .pattern import CIDRHostPattern, HostPatternList, WildcardPatternList
from .public_key import KeyImportError, SSHKey
from .public_key import SSHX509Certificate, SSHX509CertificateChain
from .public_key import import_public_key, import_certificate
from .public_key import import_certificate_subject


_EntryOptions = Mapping[str, object]


class _AuthorizedKeysOptionError(ValueError):
    """An error found while parsing an authorized_keys option"""

    def __init__(self, option: str, reason: str):
        self.option = option
        self.reason = reason
        super().__init__(reason)


class _AuthorizedKeysFromPatterns:
    """Match a from pattern list without falling back to string matching"""

    def __init__(self, patterns: str):
        self._pos_patterns = []
        self._neg_patterns = []

        if not patterns:
            raise ValueError('Empty from pattern list')

        for pattern in patterns.split(','):
            pattern = pattern.strip()

            if not pattern:
                raise ValueError('Empty from pattern')

            negate = pattern.startswith('!')
            if negate:
                pattern = pattern[1:]

                if not pattern:
                    raise ValueError('Empty negated from pattern')

            if pattern.startswith('!'):
                raise ValueError('Invalid from pattern')

            if any(ch in pattern for ch in ' \t'):
                raise ValueError('Invalid from pattern')

            if '/' in pattern:
                try:
                    matcher = CIDRHostPattern(pattern)
                except ValueError:
                    raise ValueError('Invalid CIDR from pattern') from None
            else:
                matcher = HostPatternList(pattern)

            if negate:
                self._neg_patterns.append(matcher)
            else:
                self._pos_patterns.append(matcher)

    def matches(self, host: str, addr: str, ip: Optional[IPAddress]) -> bool:
        """Return whether a host and address match this pattern list"""

        pos_match = any(pattern.matches(host, addr, ip)
                        for pattern in self._pos_patterns)
        neg_match = any(pattern.matches(host, addr, ip)
                        for pattern in self._neg_patterns)

        return pos_match and not neg_match


def _parse_option_list(line: str) -> Tuple[List[Tuple[str, Optional[str]]], str]:
    """Parse a comma-separated authorized_keys option list"""

    options: List[Tuple[str, Optional[str]]] = []
    idx = 0
    length = len(line)

    while idx < length and line[idx] in ' \t':
        idx += 1

    while idx < length:
        name_start = idx

        while (idx < length and line[idx] not in '=," \t'):
            if line[idx] == '\\':
                raise _AuthorizedKeysOptionError(
                    '<unknown>', 'Invalid escape in option name')

            idx += 1

        name = line[name_start:idx]

        if not name:
            raise _AuthorizedKeysOptionError('<unknown>',
                                             'Missing option name')

        if idx < length and line[idx] == '"':
            raise _AuthorizedKeysOptionError(
                name, 'Unexpected quote in option name')

        value: Optional[str] = None

        if idx < length and line[idx] == '=':
            idx += 1
            value_chars = []
            quoted = False

            while idx < length:
                ch = line[idx]

                if ch == '\\':
                    idx += 1

                    if idx >= length:
                        raise _AuthorizedKeysOptionError(
                            name, 'Trailing backslash in option value')

                    value_chars.append(line[idx])
                    idx += 1
                elif ch == '"':
                    quoted = not quoted
                    idx += 1
                elif not quoted and ch in ' \t,':
                    break
                else:
                    value_chars.append(ch)
                    idx += 1

            if quoted:
                raise _AuthorizedKeysOptionError(
                    name, 'Unbalanced quote in option value')

            value = ''.join(value_chars)

        options.append((name, value))

        if idx >= length:
            break

        if line[idx] == ',':
            idx += 1

            if idx >= length:
                raise _AuthorizedKeysOptionError(
                    name, 'Missing option after comma')

            continue

        return options, line[idx:].strip()

    return options, ''


class _SSHAuthorizedKeyEntry(OptionsParser):
    """An entry in an SSH authorized_keys list"""

    def __init__(self, line: str):
        super().__init__()

        self.key: Optional[SSHKey] = None
        self.cert: Optional[SSHX509Certificate] = None

        try:
            self._import_key_or_cert(line)
            return
        except KeyImportError:
            pass

        line = self._parse_options(line)

        if not line:
            raise KeyImportError('Missing key data')

        self._import_key_or_cert(line)

    def _parse_options(self, line: str) -> str:
        """Parse options in this entry with full quoting and escaping"""

        options, key_data = _parse_option_list(line)

        for option, value in options:
            self._add_parsed_option(option, value)

        return key_data

    def _add_parsed_option(self, option: str, value: Optional[str]) -> None:
        """Add an option which has already had its value unquoted"""

        if value is None:
            if option in self._handlers:
                raise _AuthorizedKeysOptionError(
                    option, 'Missing option value')

            self.options[option] = True
            return

        handler = self._handlers.get(option)

        if handler:
            try:
                handler(self, option, value)
            except _AuthorizedKeysOptionError:
                raise
            except ValueError as exc:
                raise _AuthorizedKeysOptionError(option, str(exc)) from None
        else:
            values = self.options.get(option)

            if values is None:
                self.options[option] = [value]
            elif isinstance(values, list):
                values.append(value)
            else:
                self.options[option] = [value]

    def _import_key_or_cert(self, line: str) -> None:
        """Import key or certificate in this entry"""

        try:
            self.key = import_public_key(line)
            return
        except KeyImportError:
            pass

        try:
            self.cert = cast(SSHX509Certificate, import_certificate(line))

            if ('cert-authority' in self.options and
                    self.cert.subject != self.cert.issuer):
                raise ValueError('X.509 cert-authority entries must '
                                 'contain a root CA certificate')

            return
        except KeyImportError:
            pass

        if 'cert-authority' not in self.options:
            try:
                self.key = None
                self.cert = None
                self._add_subject('subject', import_certificate_subject(line))
                return
            except KeyImportError:
                pass
            except ValueError as exc:
                raise _AuthorizedKeysOptionError(
                    'subject', str(exc)) from None

        raise KeyImportError('Unrecognized key, certificate, or subject')

    def _set_string(self, option: str, value: str) -> None:
        """Set an option with a string value"""

        self.options[option] = value

    def _add_environment(self, option: str, value: str) -> None:
        """Add an environment key/value pair"""

        if value.startswith('=') or '=' not in value:
            raise ValueError('Invalid environment entry in authorized_keys')

        name, value = value.split('=', 1)
        cast(Dict[str, str], self.options.setdefault(option, {}))[name] = value

    def _add_from(self, option: str, value: str) -> None:
        """Add a from host pattern"""

        from_patterns = cast(List[_AuthorizedKeysFromPatterns],
                             self.options.setdefault(option, []))
        from_patterns.append(_AuthorizedKeysFromPatterns(value))

    def _add_permitopen(self, option: str, value: str) -> None:
        """Add a permitopen host/port pair"""

        try:
            host, port_str = value.rsplit(':', 1)

            if host.startswith('[') and host.endswith(']'):
                host = host[1:-1]

            port = None if port_str == '*' else int(port_str)
        except ValueError:
            raise ValueError('Illegal permitopen value') from None

        permitted_opens = cast(Set[Tuple[str, Optional[int]]],
                               self.options.setdefault(option, set()))
        permitted_opens.add((host, port))

    def _add_principals(self, option: str, value: str) -> None:
        """Add a principals wildcard pattern list"""

        principal_patterns = cast(List[WildcardPatternList],
                                  self.options.setdefault(option, []))
        principal_patterns.append(WildcardPatternList(value))

    def _add_subject(self, option: str, value: str) -> None:
        """Add an X.509 subject pattern"""

        if _x509_available: # pragma: no branch
            subject_patterns = cast(List[X509NamePattern],
                                    self.options.setdefault(option, []))
            subject_patterns.append(X509NamePattern(value))
        else: # pragma: no cover
            raise ValueError('X.509 support is not available')

    _handlers = {
        'command':     _set_string,
        'environment': _add_environment,
        'from':        _add_from,
        'permitopen':  _add_permitopen,
        'principals':  _add_principals,
        'subject':     _add_subject
    }

    def match_options(self, client_host: str, client_addr: str,
                      cert_principals: Optional[Sequence[str]],
                      cert_subject: Optional['X509Name'] = None) -> bool:
        """Match "from", "principals" and "subject" options in entry"""

        from_patterns = cast(List[_AuthorizedKeysFromPatterns],
                             self.options.get('from'))

        if from_patterns:
            try:
                client_ip: Optional[IPAddress] = (ip_address(client_addr)
                                                  if client_addr else None)
            except ValueError:
                client_ip = None

            if not all(pattern.matches(client_host, client_addr, client_ip)
                       for pattern in from_patterns):
                return False

        principal_patterns = cast(List[WildcardPatternList],
                                  self.options.get('principals'))

        if principal_patterns is not None:
            if not cert_principals:
                return False

            if not all(any(pattern.matches(principal)
                           for principal in cert_principals)
                       for pattern in principal_patterns):
                return False

        subject_patterns = cast(List['X509NamePattern'],
                                self.options.get('subject'))

        if subject_patterns is not None:
            if cert_subject is None:
                return False

            if not all(pattern.matches(cert_subject)
                       for pattern in subject_patterns):
                return False

        return True


class SSHAuthorizedKeys:
    """An SSH authorized keys list"""

    def __init__(self, authorized_keys: Optional[str] = None):
        self._user_entries: List[_SSHAuthorizedKeyEntry] = []
        self._ca_entries: List[_SSHAuthorizedKeyEntry] = []
        self._x509_entries: List[_SSHAuthorizedKeyEntry] = []

        if authorized_keys:
            self.load(authorized_keys)

    def load(self, authorized_keys: str) -> None:
        """Load authorized keys data into this object"""

        for line_number, line in enumerate(authorized_keys.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            try:
                entry = _SSHAuthorizedKeyEntry(line)
            except _AuthorizedKeysOptionError as exc:
                msg = (f'Invalid authorized_keys entry on line {line_number} '
                       f'(option {exc.option}): {exc.reason}')
                logger.warning(msg)
                raise ValueError(msg) from None
            except KeyImportError:
                msg = (f'Invalid authorized_keys entry on line {line_number}: '
                       'Unable to parse key data')
                logger.warning(msg)
                raise ValueError(msg) from None
            except ValueError as exc:
                msg = (f'Invalid authorized_keys entry on line {line_number}: '
                       f'{exc}')
                logger.warning(msg)
                raise ValueError(msg) from None

            if entry.key:
                if 'cert-authority' in entry.options:
                    self._ca_entries.append(entry)
                else:
                    self._user_entries.append(entry)
            else:
                self._x509_entries.append(entry)

        if (not self._user_entries and not self._ca_entries and
                not self._x509_entries):
            raise ValueError('No valid entries found')

    def validate(self, key: SSHKey, client_host: str, client_addr: str,
                 cert_principals: Optional[Sequence[str]] = None,
                 ca: bool = False) -> Optional[_EntryOptions]:
        """Return whether a public key or CA is valid for authentication"""

        for entry in self._ca_entries if ca else self._user_entries:
            if (entry.key == key and
                    entry.match_options(client_host, client_addr,
                                        cert_principals)):
                return entry.options

        return None

    def validate_x509(self, cert: SSHX509CertificateChain, client_host: str,
                      client_addr: str) -> Tuple[Optional[_EntryOptions],
                                                 Optional[SSHX509Certificate]]:
        """Return whether an X.509 certificate is valid for authentication"""

        for entry in self._x509_entries:
            if (entry.cert and 'cert-authority' not in entry.options and
                    (cert.key != entry.cert.key or
                     cert.subject != entry.cert.subject)):
                continue # pragma: no cover (work around bug in coverage tool)

            if entry.match_options(client_host, client_addr,
                                   cert.user_principals, cert.subject):
                return entry.options, entry.cert

        return None, None

def import_authorized_keys(data: str) -> SSHAuthorizedKeys:
    """Import SSH authorized keys

       This function imports public keys and associated options in
       OpenSSH authorized keys format.

       :param data:
           The key data to import.
       :type data: `str`

       :returns: An :class:`SSHAuthorizedKeys` object

    """

    return SSHAuthorizedKeys(data)


def read_authorized_keys(filelist: Union[FilePath, Sequence[FilePath]]) -> \
        SSHAuthorizedKeys:
    """Read SSH authorized keys from a file or list of files

       This function reads public keys and associated options in
       OpenSSH authorized_keys format from a file or list of files.

       :param filelist:
           The file or list of files to read the keys from.
       :type filelist: `PurePath`, `str`, or a list of these

       :returns: An :class:`SSHAuthorizedKeys` object

    """

    authorized_keys = SSHAuthorizedKeys()

    if isinstance(filelist, (PurePath, str)):
        files: Sequence[FilePath] = [filelist]
    else:
        files = filelist

    for filename in files:
        authorized_keys.load(read_file(filename, 'r'))

    return authorized_keys
