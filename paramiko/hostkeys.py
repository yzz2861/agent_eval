# Copyright (C) 2006-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.


import binascii
import ipaddress
import os
import re
from base64 import decodebytes, encodebytes
from collections.abc import MutableMapping
from hashlib import sha1
from hmac import HMAC

from paramiko.pkey import PKey, UnknownKeyType
from paramiko.ssh_exception import SSHException
from paramiko.util import b, constant_time_bytes_eq, get_logger, u

SSH_DEFAULT_PORT = 22


class HostKeyParseError(SSHException):
    """
    Raised for malformed lines encountered while parsing a known_hosts file.

    Unlike an unknown host or a key-type conflict, the line itself could not
    be turned into a `.HostKeyEntry`.
    """

    def __init__(self, line, lineno=None, cause=None):
        self.line = line
        self.lineno = lineno
        self.cause = cause
        location = "line {}".format(lineno) if lineno else "unknown line"
        msg = "Invalid known_hosts entry on {}: {!r}".format(location, line)
        if cause is not None:
            msg = "{} ({})".format(msg, cause)
        super().__init__(msg)


class DuplicateHostKeyEntry(SSHException):
    """
    Raised (in strict mode) when the exact same host/key-type/key entry is
    seen more than once.
    """

    def __init__(self, hostname, keytype, lineno=None):
        self.hostname = hostname
        self.keytype = keytype
        self.lineno = lineno
        super().__init__(
            "Duplicate {} host key for {!r} on line {}".format(
                keytype, hostname, lineno
            )
        )


class ConflictingHostKeyType(SSHException):
    """
    Raised (in strict mode) when one host/key-type pair maps to two
    different keys.
    """

    def __init__(self, hostname, keytype, existing, new, lineno=None):
        self.hostname = hostname
        self.keytype = keytype
        self.existing = existing
        self.new = new
        self.lineno = lineno
        super().__init__(
            "Conflicting {} host keys for {!r} on line {}".format(
                keytype, hostname, lineno
            )
        )


class UnknownHostKey(KeyError):
    """
    Raised by strict lookups when no entry (including acceptable wildcard or
    hashed entries) matches the requested host.
    """

    def __init__(self, hostname):
        self.hostname = hostname
        super().__init__("No host key found for {!r}".format(hostname))


class NormalizedHostKey:
    """
    Canonical representation of a known_hosts host field.

    The same logical endpoint may be written several ways (upper/lower case,
    trailing DNS dot, bracketed IPv6, ``[host]:port``); this class holds the
    normalized components so plain-text storage and hashed HMAC input always
    agree.

    :ivar str host: normalized hostname or IP literal, without brackets
    :ivar int port: port number (`SSH_DEFAULT_PORT` when absent)
    :ivar str scope_id: IPv6 zone/scope identifier (e.g. ``eth0``), if any
    :ivar str family: ``"dns"``, ``"ipv4"`` or ``"ipv6"``
    :ivar bool hashed: whether the source field was an ``|1|`` hash
    :ivar bool wildcard: whether the source field contains a wildcard
    :ivar str raw: original text as found in the file / supplied by callers
    """

    def __init__(
        self,
        host,
        port=SSH_DEFAULT_PORT,
        scope_id="",
        family="dns",
        hashed=False,
        wildcard=False,
        raw=None,
    ):
        self.host = host
        self.port = port
        self.scope_id = scope_id
        self.family = family
        self.hashed = hashed
        self.wildcard = wildcard
        self.raw = raw if raw is not None else self.canonical

    @property
    def canonical(self):
        """Canonical OpenSSH-style key, including port when non-default."""
        host = self.host
        if self.family == "ipv6" and self.scope_id:
            host = "{}%{}".format(host, self.scope_id)
        if self.port != SSH_DEFAULT_PORT:
            return "[{}]:{}".format(host, self.port)
        return host

    @property
    def bare(self):
        """Canonical host without any explicit port."""
        host = self.host
        if self.family == "ipv6" and self.scope_id:
            host = "{}%{}".format(host, self.scope_id)
        return host

    def __str__(self):
        return self.canonical

    def __repr__(self):
        return (
            "NormalizedHostKey(host={!r}, port={!r}, family={!r}, "
            "scope_id={!r}, hashed={!r}, wildcard={!r})"
        ).format(
            self.host,
            self.port,
            self.family,
            self.scope_id,
            self.hashed,
            self.wildcard,
        )


def _split_bracketed(value):
    if not value.startswith("["):
        return value, None
    end = value.find("]")
    if end == -1:
        raise HostKeyParseError(value, cause="unbalanced '[' bracket")
    inside = value[1:end]
    tail = value[end + 1 :]
    if tail and not tail.startswith(":"):
        raise HostKeyParseError(value, cause="text after closing ']'")
    port_text = tail[1:] if tail else ""
    return inside, port_text


def _parse_port(port_text, raw):
    if port_text is None or port_text == "":
        return SSH_DEFAULT_PORT
    if not port_text.isdigit():
        raise HostKeyParseError(raw, cause="non-numeric port")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise HostKeyParseError(raw, cause="port out of range")
    return port


def _normalize_host_part(host, raw):
    scope_id = ""
    if "%" in host:
        host, scope_id = host.split("%", 1)
        if not scope_id:
            raise HostKeyParseError(raw, cause="empty IPv6 scope id")
    address_part = host
    try:
        ip = ipaddress.ip_address(address_part)
    except ValueError:
        ip = None
    if ip is not None:
        if scope_id and ip.version != 6:
            raise HostKeyParseError(
                raw, cause="scope id is only valid for IPv6 addresses"
            )
        if ip.version == 4:
            family = "ipv4"
        else:
            family = "ipv6"
        normalized = str(ip)
    else:
        family = "dns"
        if any(ch in host for ch in ("[", "]")):
            raise HostKeyParseError(raw, cause="unexpected brackets")
        normalized = host.lower()
        if normalized.endswith("."):
            normalized = normalized[:-1]
        if not normalized or normalized.endswith("."):
            raise HostKeyParseError(raw, cause="empty DNS label")
        for label in normalized.split("."):
            if not label:
                raise HostKeyParseError(raw, cause="empty DNS label")
    wildcard = any(ch in host for ch in ("*", "?"))
    return normalized, scope_id, family, wildcard


def normalize_host_key(value):
    """
    Parse and normalize a known_hosts host field.

    Accepted forms include plain DNS names, IPv4/IPv6 literals (optionally
    with an IPv6 scope id), ``[host]:port`` and ``|1|`` hashed fields.

    :param str value: raw host field
    :rtype: `.NormalizedHostKey`
    :raises `.HostKeyParseError`: for syntactically invalid fields
    """
    raw = value
    if not isinstance(value, str) or value == "":
        raise HostKeyParseError(value, cause="empty host field")
    if value.startswith("|1|"):
        parts = value.split("|")
        if len(parts) != 4 or parts[1] != "1":
            raise HostKeyParseError(value, cause="malformed hashed host")
        return NormalizedHostKey(
            host=value,
            family="hash",
            hashed=True,
            raw=raw,
        )
    if value.startswith("["):
        inside, port_text = _split_bracketed(value)
        port = _parse_port(port_text, raw)
        host, scope_id, family, wildcard = _normalize_host_part(inside, raw)
        return NormalizedHostKey(
            host=host,
            port=port,
            scope_id=scope_id,
            family=family,
            wildcard=wildcard,
            raw=raw,
        )
    bare_ip_probe = value.split("%", 1)[0]
    try:
        bare_ip = ipaddress.ip_address(bare_ip_probe)
    except ValueError:
        bare_ip = None
    if bare_ip is not None:
        scope_suffix = value.split("%", 1)[1] if "%" in value else ""
        if ":" in scope_suffix:
            raise HostKeyParseError(
                value,
                cause="scoped IPv6 with port requires bracket syntax",
            )
        host, scope_id, family, wildcard = _normalize_host_part(value, raw)
        return NormalizedHostKey(
            host=host,
            scope_id=scope_id,
            family=family,
            wildcard=wildcard,
            raw=raw,
        )
    if ":" in value:
        host_part, port_text = value.rsplit(":", 1)
        port = _parse_port(port_text, raw)
        host, scope_id, family, wildcard = _normalize_host_part(host_part, raw)
        if family == "ipv6":
            raise HostKeyParseError(
                raw,
                cause="IPv6 addresses with a port require bracket syntax",
            )
        return NormalizedHostKey(
            host=host,
            port=port,
            scope_id=scope_id,
            family=family,
            wildcard=wildcard,
            raw=raw,
        )
    host, scope_id, family, wildcard = _normalize_host_part(value, raw)
    return NormalizedHostKey(
        host=host,
        scope_id=scope_id,
        family=family,
        wildcard=wildcard,
        raw=raw,
    )


def _label_matches(pattern, label):
    """Match one DNS label; wildcards never cross a '.' boundary."""
    regex = "".join(
        "[^.]" if ch == "?" else "[^.]*" if ch == "*" else re.escape(ch)
        for ch in pattern
    )
    return re.fullmatch(regex, label) is not None


def host_matches(pattern, candidate):
    """
    Compare two normalized host fields.

    ``*`` matches any number of characters within one DNS label and ``?``
    matches a single character within one label; neither can consume dots.
    Ports must agree exactly: a wildcard name on the default port never
    matches an explicit non-default-port lookup.
    """
    if pattern.hashed or candidate.hashed:
        return False
    if pattern.port != candidate.port:
        return False
    if pattern.family != candidate.family:
        return False
    if pattern.scope_id != candidate.scope_id:
        return False
    pattern_labels = pattern.host.split(".")
    candidate_labels = candidate.host.split(".")
    if len(pattern_labels) != len(candidate_labels):
        return False
    return all(
        _label_matches(pattern_label, candidate_label)
        for pattern_label, candidate_label in zip(
            pattern_labels, candidate_labels
        )
    )


class HostKeys(MutableMapping):
    """
    Representation of an OpenSSH-style "known hosts" file.  Host keys can be
    read from one or more files, and then individual hosts can be looked up to
    verify server keys during SSH negotiation.

    A `.HostKeys` object can be treated like a dict; any dict lookup is
    equivalent to calling `lookup`.

    .. versionadded:: 1.5.3
    """

    def __init__(self, filename=None, strict=False):
        """
        Create a new HostKeys object, optionally loading keys from an OpenSSH
        style host-key file.

        :param str filename: filename to load host keys from, or ``None``
        :param bool strict: when true, lookups never fall back from an
            explicit port to a bare-host entry, and `load` raises on bad,
            duplicate or conflicting entries instead of skipping them
        """
        # emulate a dict of { hostname: { keytype: PKey } }
        self._entries = []
        self.strict = strict
        self.load_errors = []
        if filename is not None:
            self.load(filename)

    def add(self, hostname, keytype, key):
        """
        Add a host key entry to the table.  Any existing entry for a
        ``(hostname, keytype)`` pair will be replaced.

        :param str hostname: the hostname (or IP) to add; ``[host]:port``,
            bracketed IPv6 and trailing-dot forms are normalized
        :param str keytype: key type (in ``"ssh-<type>"`` format)
        :param .PKey key: the key to add
        """
        normalized = normalize_host_key(hostname)
        canonical_hostname = (
            normalized.raw if normalized.hashed else normalized.canonical
        )
        for e in self._entries:
            if e.key.get_name() != keytype:
                continue
            for entry_host in e.normalized_hostnames:
                if (
                    not entry_host.hashed
                    and not entry_host.wildcard
                    and not normalized.hashed
                    and not normalized.wildcard
                    and host_matches(entry_host, normalized)
                ):
                    e.key = key
                    return
            if (
                normalized.hashed
                and canonical_hostname in e.hostnames
                and e.key.get_name() == keytype
            ):
                e.key = key
                return
        self._entries.append(HostKeyEntry([canonical_hostname], key))

    def load(self, filename):
        """
        Read a file of known SSH host keys, in the format used by OpenSSH.
        This type of file unfortunately doesn't exist on Windows, but on
        posix, it will usually be stored in
        ``os.path.expanduser("~/.ssh/known_hosts")``.

        If this method is called multiple times, the host keys are merged,
        not cleared.  So multiple calls to `load` will just call `add`,
        replacing any existing entries and adding new ones.

        :param str filename: name of the file to read host keys from

        :raises: ``IOError`` -- if there was an error reading the file
        """
        self.load_errors = []
        with open(filename, "r") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if (len(line) == 0) or (line[0] == "#"):
                    continue
                try:
                    entry = HostKeyEntry.from_line(line, lineno)
                except SSHException as exc:
                    self.load_errors.append(exc)
                    if self.strict:
                        raise
                    continue
                if entry is not None:
                    self._merge_loaded_entry(entry, lineno)

    def _merge_loaded_entry(self, entry, lineno):
        surviving_hostnames = []
        for hostname in entry.hostnames:
            normalized = normalize_host_key(hostname)
            conflict = self._find_conflict(normalized, entry.key)
            if conflict is None:
                surviving_hostnames.append(hostname)
                continue
            conflict_entry, existing_key = conflict
            if existing_key.asbytes() == entry.key.asbytes():
                error = DuplicateHostKeyEntry(
                    hostname, entry.key.get_name(), lineno
                )
            else:
                error = ConflictingHostKeyType(
                    hostname,
                    entry.key.get_name(),
                    existing_key,
                    entry.key,
                    lineno,
                )
            self.load_errors.append(error)
            if self.strict:
                raise error
        entry.hostnames = surviving_hostnames
        if entry.hostnames:
            self._entries.append(entry)

    def _find_conflict(self, normalized, key):
        for entry in self._entries:
            if entry.key is None or entry.key.get_name() != key.get_name():
                continue
            for entry_host in entry.normalized_hostnames:
                if entry_host.hashed or normalized.hashed:
                    continue
                if host_matches(entry_host, normalized):
                    return entry, entry.key
        return None

    def save(self, filename):
        """
        Save host keys into a file, in the format used by OpenSSH.  The order
        of keys in the file will be preserved when possible (if these keys were
        loaded from a file originally).  The single exception is that combined
        lines will be split into individual key lines, which is arguably a bug.

        :param str filename: name of the file to write

        :raises: ``IOError`` -- if there was an error writing the file

        .. versionadded:: 1.6.1
        """
        with open(filename, "w") as f:
            for e in self._entries:
                line = e.to_line()
                if line:
                    f.write(line)

    def lookup(self, hostname):
        """
        Find a hostkey entry for a given hostname or IP.  If no entry is found,
        ``None`` is returned.  Otherwise a dictionary of keytype to key is
        returned.

        :param str hostname: the hostname (or IP) to lookup
        :return: dict of `str` -> `.PKey` keys associated with this host
            (or ``None``)
        """

        class SubDict(MutableMapping):
            def __init__(self, hostname, entries, hostkeys):
                self._hostname = hostname
                self._entries = entries
                self._hostkeys = hostkeys

            def __iter__(self):
                for k in self.keys():
                    yield k

            def __len__(self):
                return len(self.keys())

            def __delitem__(self, key):
                for e in list(self._entries):
                    if e.key.get_name() == key:
                        self._entries.remove(e)
                        break
                else:
                    raise KeyError(key)

            def __getitem__(self, key):
                for e in self._entries:
                    if e.key.get_name() == key:
                        return e.key
                raise KeyError(key)

            def __setitem__(self, key, val):
                for e in self._entries:
                    if e.key is None:
                        continue
                    if e.key.get_name() == key:
                        # replace
                        e.key = val
                        break
                else:
                    # add a new one
                    normalized = normalize_host_key(hostname)
                    canonical = (
                        normalized.raw
                        if normalized.hashed
                        else normalized.canonical
                    )
                    e = HostKeyEntry([canonical], val)
                    self._entries.append(e)
                    self._hostkeys._entries.append(e)

            def keys(self):
                return [
                    e.key.get_name()
                    for e in self._entries
                    if e.key is not None
                ]

        result = self.explain(hostname)
        if not result.matched:
            return None
        return SubDict(hostname, result.entries, self)

    def explain(self, hostname):
        """
        Detailed counterpart of `lookup` that records *why* entries did or
        did not match.

        :param str hostname: the hostname (or IP) to lookup
        :return: `.HostKeyLookupResult`
        """
        candidate = normalize_host_key(hostname)
        entries = []
        reasons = []
        for entry in self._entries:
            matched, reason = entry.matches(candidate, self.hash_host)
            if matched:
                entries.append(entry)
            elif reason:
                reasons.append(reason)
        fallback_used = False
        if (
            not entries
            and not self.strict
            and candidate.port != SSH_DEFAULT_PORT
        ):
            bare_candidate = normalize_host_key(candidate.bare)
            for entry in self._entries:
                if any(
                    host.hashed or host.wildcard
                    for host in entry.normalized_hostnames
                ):
                    continue
                matched, reason = entry.matches(
                    bare_candidate, self.hash_host
                )
                if matched:
                    entries.append(entry)
                    fallback_used = True
                elif reason:
                    reasons.append(reason)
        return HostKeyLookupResult(
            hostname=hostname,
            candidate=candidate,
            entries=entries,
            fallback_used=fallback_used,
            reasons=reasons,
        )

    def _hostname_matches(self, hostname, entry):
        """
        Tests whether ``hostname`` string matches given SubDict ``entry``.

        :returns bool:
        """
        candidate = normalize_host_key(hostname)
        matched, _ = entry.matches(candidate, self.hash_host)
        if matched:
            return True
        if not self.strict and candidate.port != SSH_DEFAULT_PORT:
            if any(
                host.hashed or host.wildcard
                for host in entry.normalized_hostnames
            ):
                return False
            bare = normalize_host_key(candidate.bare)
            matched, _ = entry.matches(bare, self.hash_host)
            return matched
        return False

    def check(self, hostname, key):
        """
        Return True if the given key is associated with the given hostname
        in this dictionary.

        :param str hostname: hostname (or IP) of the SSH server
        :param .PKey key: the key to check
        :return:
            ``True`` if the key is associated with the hostname; else ``False``
        """
        k = self.lookup(hostname)
        if k is None:
            return False
        host_key = k.get(key.get_name(), None)
        if host_key is None:
            return False
        return host_key.asbytes() == key.asbytes()

    def clear(self):
        """
        Remove all host keys from the dictionary.
        """
        self._entries = []

    def __iter__(self):
        for k in self.keys():
            yield k

    def __len__(self):
        return len(self.keys())

    def __getitem__(self, key):
        ret = self.lookup(key)
        if ret is None:
            raise KeyError(key)
        return ret

    def __delitem__(self, key):
        index = None
        for i, entry in enumerate(self._entries):
            if self._hostname_matches(key, entry):
                index = i
                break
        if index is None:
            raise KeyError(key)
        self._entries.pop(index)

    def __setitem__(self, hostname, entry):
        # don't use this please.
        normalized = normalize_host_key(hostname)
        canonical_hostname = (
            normalized.raw if normalized.hashed else normalized.canonical
        )
        if len(entry) == 0:
            self._entries.append(HostKeyEntry([canonical_hostname], None))
            return
        for key_type in entry.keys():
            found = False
            for e in self._entries:
                if e.key is None or e.key.get_name() != key_type:
                    continue
                for entry_host in e.normalized_hostnames:
                    if (
                        not entry_host.hashed
                        and not entry_host.wildcard
                        and not normalized.hashed
                        and not normalized.wildcard
                        and host_matches(entry_host, normalized)
                    ):
                        # replace
                        e.key = entry[key_type]
                        found = True
                        break
            if not found:
                self._entries.append(
                    HostKeyEntry([canonical_hostname], entry[key_type])
                )

    def keys(self):
        ret = []
        for e in self._entries:
            for h in e.hostnames:
                if h not in ret:
                    ret.append(h)
        return ret

    def values(self):
        ret = []
        for k in self.keys():
            ret.append(self.lookup(k))
        return ret

    @staticmethod
    def hash_host(hostname, salt=None):
        """
        Return a "hashed" form of the hostname, as used by OpenSSH when storing
        hashed hostnames in the known_hosts file.

        :param str hostname: the hostname to hash; it is normalized with the
            same rules (brackets, IPv6 scope, trailing dot, case and port)
            used for plain-text entries before HMAC input
        :param str salt: optional salt to use when hashing
            (must be 20 bytes long)
        :return: the hashed hostname as a `str`
        """
        if not str(hostname).startswith("|1|"):
            hostname = normalize_host_key(hostname).canonical
        if salt is None:
            salt = os.urandom(sha1().digest_size)
        else:
            if salt.startswith("|1|"):
                salt = salt.split("|")[2]
            salt = decodebytes(b(salt))
        assert len(salt) == sha1().digest_size
        hmac = HMAC(salt, b(hostname), sha1).digest()
        hostkey = "|1|{}|{}".format(u(encodebytes(salt)), u(encodebytes(hmac)))
        return hostkey.replace("\n", "")


class InvalidHostKey(Exception):
    def __init__(self, line, exc):
        self.line = line
        self.exc = exc
        self.args = (line, exc)


class HostKeyLookupResult:
    """
    Explainable outcome of a `.HostKeys.explain` lookup.

    :ivar str hostname: hostname as requested by the caller
    :ivar NormalizedHostKey candidate: normalized view of the request
    :ivar list entries: `.HostKeyEntry` objects that matched
    :ivar bool fallback_used: True when a bare-host entry matched a
        non-default-port request because strict mode was disabled
    :ivar list reasons: human-readable notes about near misses
    """

    def __init__(self, hostname, candidate, entries, fallback_used, reasons):
        self.hostname = hostname
        self.candidate = candidate
        self.entries = entries
        self.fallback_used = fallback_used
        self.reasons = reasons

    @property
    def matched(self):
        return bool(self.entries)

    @property
    def key_types(self):
        return [entry.key.get_name() for entry in self.entries]

    def require(self):
        """Return matched entries or raise `.UnknownHostKey`."""
        if not self.matched:
            raise UnknownHostKey(self.hostname)
        return self.entries

    def __repr__(self):
        return (
            "HostKeyLookupResult(hostname={!r}, matched={!r}, "
            "fallback_used={!r}, key_types={!r})"
        ).format(
            self.hostname, self.matched, self.fallback_used, self.key_types
        )


class HostKeyEntry:
    """
    Representation of a line in an OpenSSH-style "known hosts" file.
    """

    def __init__(self, hostnames=None, key=None):
        self.valid = (hostnames is not None) and (key is not None)
        self.hostnames = hostnames
        self.key = key
        self.normalized_hostnames = (
            [normalize_host_key(host) for host in hostnames]
            if hostnames is not None
            else []
        )

    @classmethod
    def from_line(cls, line, lineno=None):
        """
        Parses the given line of text to find the names for the host,
        the type of key, and the key data. The line is expected to be in the
        format used by the OpenSSH known_hosts file. Fields are separated by a
        single space or tab.

        Lines are expected to not have leading or trailing whitespace.
        We don't bother to check for comments or empty lines.  All of
        that should be taken care of before sending the line to us.

        :param str line: a line from an OpenSSH known_hosts file
        """
        log = get_logger("paramiko.hostkeys")
        fields = re.split(" |\t", line)
        if len(fields) < 3:
            # Bad number of fields
            msg = "Not enough fields found in known_hosts in line {} ({!r})"
            log.info(msg.format(lineno, line))
            raise HostKeyParseError(
                line, lineno, cause="expected at least 3 fields"
            )
        fields = fields[:3]

        names, key_type, key = fields
        raw_names = names.split(",")
        normalized_names = []
        for name in raw_names:
            try:
                normalized = normalize_host_key(name)
            except HostKeyParseError as exc:
                exc.lineno = lineno
                raise
            normalized_names.append(normalized)
        names = [
            normalized.raw if normalized.hashed else normalized.canonical
            for normalized in normalized_names
        ]

        # Decide what kind of key we're looking at and create an object
        # to hold it accordingly.
        try:
            # TODO: this grew organically and doesn't seem /wrong/ per se (file
            # read -> unicode str -> bytes for base64 decode -> decoded bytes);
            # but in Python 3 forever land, can we simply use
            # `base64.b64decode(str-from-file)` here?
            key_bytes = decodebytes(b(key))
        except binascii.Error as e:
            raise HostKeyParseError(line, lineno, cause=e) from e

        try:
            return cls(names, PKey.from_type_string(key_type, key_bytes))
        except UnknownKeyType:
            # TODO (backwards incompat): consider changing HostKeys API so this
            # just raises naturally and the exception is muted higher up in the
            # stack?
            log.info("Unable to handle key of type {}".format(key_type))
            return None

    def matches(self, candidate, hash_host):
        """
        Test whether a normalized lookup candidate matches this entry.

        Returns ``(bool, reason)``; ``reason`` is populated for explainable
        near misses such as port or key-scope differences.
        """
        reasons = []
        for stored in self.normalized_hostnames:
            if stored.hashed:
                if candidate.hashed:
                    continue
                hashed = hash_host(candidate.canonical, stored.raw)
                if constant_time_bytes_eq(hashed, stored.raw):
                    return True, None
                continue
            if candidate.hashed:
                continue
            if host_matches(stored, candidate):
                return True, None
            reason = self._mismatch_reason(stored, candidate)
            if reason:
                reasons.append(reason)
        return False, reasons[0] if reasons else None

    @staticmethod
    def _mismatch_reason(stored, candidate):
        if stored.port != candidate.port:
            return (
                "port mismatch: entry uses port {}, lookup requested "
                "port {}".format(stored.port, candidate.port)
            )
        if stored.family != candidate.family:
            return "address family mismatch: {} vs {}".format(
                stored.family, candidate.family
            )
        if stored.scope_id != candidate.scope_id:
            return "IPv6 scope id mismatch: {!r} vs {!r}".format(
                stored.scope_id, candidate.scope_id
            )
        return None

    def to_line(self):
        """
        Returns a string in OpenSSH known_hosts file format, or None if
        the object is not in a valid state.  A trailing newline is
        included.
        """
        if self.valid:
            return "{} {} {}\n".format(
                ",".join(self.hostnames),
                self.key.get_name(),
                self.key.get_base64(),
            )
        return None

    def __repr__(self):
        return "<HostKeyEntry {!r}: {!r}>".format(self.hostnames, self.key)
