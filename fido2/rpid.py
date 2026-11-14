# Copyright (c) 2018 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""
These functions validate RP_ID, APP_ID and origins according to simplified TLD+1
rules, using a bundled copy of the public suffix list fetched from:

  https://publicsuffix.org/list/public_suffix_list.dat

RP ID validation and origin validation are kept as separate, composable steps:

* An RP ID must be a registrable domain (or an IP literal) that is equal to the
  origin host, or a parent domain of it. Public suffixes may not be used as RP
  IDs for subdomains. Hosts are normalized for case, trailing dots, IDNA and
  IPv4/IPv6 before any comparison.
* An origin must match an entry of the allow list exactly, comparing scheme,
  host and port. Userinfo, paths and fragments are not part of an origin and
  are rejected. An empty allow list denies every origin.

Advanced APP_ID values pointing to JSON files containing valid facets are not
supported by this implementation.
"""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Sequence
from urllib.parse import urlparse

tld_fname = os.path.join(os.path.dirname(__file__), "public_suffix_list.dat")
with open(tld_fname, "rb") as f:
    _suffix_set: set[str] = set()
    _wildcard_set: set[str] = set()
    _exception_set: set[str] = set()
    for _line in f:
        _entry = _line.decode("utf8").strip()
        if not _entry or _entry.startswith("//"):
            continue
        if _entry.startswith("!"):
            _exception_set.add(_entry[1:])
        elif _entry.startswith("*."):
            _wildcard_set.add(_entry[2:])
        else:
            _suffix_set.add(_entry)

# Keep `suffixes` as a list for backward compatibility
suffixes = sorted(
    _suffix_set | {f"*.{w}" for w in _wildcard_set} | {f"!{e}" for e in _exception_set}
)

_LABEL_RE = re.compile(rb"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
_SCHEMES = ("http", "https")
_DEFAULT_PORTS = {"http": 80, "https": 443}


class RpIdError(ValueError):
    """Base class for RP ID and origin validation errors."""


class InvalidConfigurationError(RpIdError):
    """Raised when an RP ID or an origin allow list is not valid."""


class RpIdMismatchError(RpIdError):
    """Raised when an RP ID is not usable for an origin's host."""


class OriginMismatchError(RpIdError):
    """Raised when an origin is not part of the configured allow list."""


class _OriginParseError(ValueError):
    """Raised internally when an origin string cannot be parsed."""


def _is_public_suffix(domain: str) -> bool:
    """Check if a domain is a public suffix per the PSL algorithm.

    https://github.com/publicsuffix/list/wiki/Format
    """
    labels = domain.split(".")
    # Exception rules take precedence. A matching exception entry means the
    # domain is a public suffix minus its leading label, so it is itself a
    # public suffix only when there is nothing above the exception entry.
    for index in range(len(labels)):
        if ".".join(labels[index:]) in _exception_set:
            return index == 1

    # Find the longest matching rule and compare how many labels it covers.
    matched_labels = 1  # The implicit "*" rule always matches the last label.
    for index in range(len(labels)):
        candidate = ".".join(labels[index:])
        if candidate in _suffix_set:
            matched_labels = max(matched_labels, len(labels) - index)
        if index > 0 and candidate in _wildcard_set:
            # "*.candidate" covers the wildcard label plus the rule labels.
            matched_labels = max(matched_labels, len(labels) - index + 1)
    return matched_labels >= len(labels)


def _strip_trailing_dot(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Expected a string value.")
    if value.endswith("."):
        value = value[:-1]
    if not value or value.endswith("."):
        raise ValueError("Empty or malformed domain label.")
    return value


def _normalize_domain(domain: str) -> str:
    if not isinstance(domain, str):
        raise ValueError("Domain must be a string.")
    domain = _strip_trailing_dot(domain)
    labels = domain.split(".")
    normalized_labels = []
    for label in labels:
        if not label:
            raise ValueError("Empty label in domain.")
        label = label.lower()
        try:
            encoded = label.encode("idna")
        except UnicodeError as e:
            raise ValueError("Domain label cannot be encoded using IDNA.") from e
        if not _LABEL_RE.fullmatch(encoded):
            raise ValueError("Invalid character in domain label.")
        normalized_labels.append(encoded.decode("ascii"))
    normalized = ".".join(normalized_labels)
    if len(normalized) > 253:
        raise ValueError("Domain is too long.")
    return normalized


def _normalize_host(host: str) -> str:
    """Normalize a host to ASCII lowercase, including IDNA and IP literals."""
    if not isinstance(host, str) or not host:
        raise ValueError("Host must be a non-empty string.")
    host = _strip_trailing_dot(host)
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return _normalize_domain(host)
    return str(ip)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _is_secure_context(scheme: str, host: str) -> bool:
    # Note that Webauthn requires a secure context, i.e. an origin with https
    # scheme. However, most browsers also treat http://localhost as a secure
    # context. See
    # https://groups.google.com/a/chromium.org/g/blink-dev/c/RC9dSw-O3fE/m/E3_0XaT0B0BAAJ
    if scheme == "https":
        return True
    if scheme == "http":
        return host == "localhost" or (
            host.endswith(".localhost") and not _is_ip_literal(host)
        )
    return False


def _parse_origin(origin: str) -> tuple[str, str, int]:
    """Parse and normalize an origin into a (scheme, host, port) tuple.

    Raises ValueError for anything that is not an exact, unadorned WebAuthn
    origin: userinfo, paths, queries and fragments are rejected.
    """
    if not isinstance(origin, str) or not origin:
        raise _OriginParseError("Origin must be a non-empty string.")
    if "\\" in origin:
        raise _OriginParseError("Backslashes are not allowed in origins.")

    url = urlparse(origin)
    if url.scheme not in _SCHEMES:
        raise _OriginParseError("Origin scheme must be http or https.")
    if not url.hostname:
        raise _OriginParseError("Origin must contain a host.")
    if url.username is not None or url.password is not None:
        raise _OriginParseError("Userinfo is not allowed in an origin.")
    if url.path not in ("", "/") or url.query or url.fragment or url.params:
        raise _OriginParseError("Origin must not contain a path or fragment.")
    try:
        port = url.port
    except ValueError as e:
        raise _OriginParseError("Invalid port in origin.") from e
    if port is None:
        port = _DEFAULT_PORTS[url.scheme]

    try:
        host = _normalize_host(url.hostname)
    except ValueError as e:
        raise _OriginParseError("Invalid host in origin.") from e
    return url.scheme, host, port


def verify_rp_id(rp_id: str, origin: str) -> bool:
    """Checks if a Webauthn RP ID is usable for a given origin.

    The RP ID must equal the normalized origin host, or be a non-public-suffix
    parent domain of it. Case, trailing dots, IDNA and IP literal formatting
    are normalized before comparison. This function never raises and returns
    False for any malformed input.

    :param rp_id: The RP ID to validate.
    :param origin: The origin of the request.
    :return: True if the RP ID is usable by the origin, False if not.
    """
    try:
        scheme, host, _ = _parse_origin(origin)
        normalized_rp_id = _normalize_host(_strip_trailing_dot(rp_id))
    except (ValueError, TypeError):
        return False

    if not _is_secure_context(scheme, host):
        return False
    if normalized_rp_id == host:
        return True
    # IP literals and public suffixes can only be used as exact RP IDs.
    if _is_ip_literal(normalized_rp_id) or _is_ip_literal(host):
        return False
    # Browsers treat every *.localhost origin as belonging to localhost.
    if normalized_rp_id == "localhost":
        return host.endswith(".localhost")
    if _is_public_suffix(normalized_rp_id):
        return False
    return host.endswith("." + normalized_rp_id)


def verify_origin(origin: str, allowed_origins: Sequence[str]) -> bool:
    """Checks that an origin exactly matches an entry of an allow list.

    Scheme, host and port are compared after normalization. An empty allow
    list rejects every origin. Malformed origins never raise and are simply
    rejected.

    :param origin: The origin of the request.
    :param allowed_origins: Exact origins accepted by the relying party.
    :return: True if the origin is allowed, False if not.
    """
    try:
        parsed = _parse_origin(origin)
        allowed = {_parse_origin(item) for item in allowed_origins}
    except (ValueError, TypeError):
        return False
    return parsed in allowed


class RpIdPolicy:
    """Shared validation policy for registration and authentication.

    :param rp_id: The RP ID served by the relying party. Must be a registrable
        domain (not a public suffix) or an IP literal.
    :param allowed_origins: Exact origins accepted by the relying party. When
        an empty list is given every origin is rejected. When None, the legacy
        RP ID suffix behavior is used instead of an explicit allow list.
    """

    def __init__(
        self, rp_id: str, allowed_origins: Sequence[str] | None = None
    ) -> None:
        try:
            self._rp_id = _normalize_host(_strip_trailing_dot(rp_id))
        except (ValueError, TypeError) as e:
            raise InvalidConfigurationError("Invalid RP ID in configuration.") from e
        if (
            self._rp_id != "localhost"
            and not _is_ip_literal(self._rp_id)
            and _is_public_suffix(self._rp_id)
        ):
            raise InvalidConfigurationError(
                "RP ID must not be a public suffix."
            )

        self._legacy_allow_list = allowed_origins is None
        if self._legacy_allow_list:
            self._allowed_origins: frozenset[tuple[str, str, int]] = frozenset()
            return
        if isinstance(allowed_origins, str) or not isinstance(
            allowed_origins, (list, tuple, set, frozenset)
        ):
            raise InvalidConfigurationError(
                "Allowed origins must be provided as a list of strings."
            )
        parsed_origins = set()
        for item in allowed_origins:
            try:
                parsed_origins.add(_parse_origin(item))
            except (ValueError, TypeError) as e:
                raise InvalidConfigurationError(
                    "Invalid entry in allowed origins configuration."
                ) from e
        self._allowed_origins = frozenset(parsed_origins)

    @property
    def rp_id(self) -> str:
        return self._rp_id

    def verify_rp_id(self, rp_id: str | None = None, origin: str = "") -> bool:
        """Return True if the RP ID is usable for the origin."""
        return verify_rp_id(self._rp_id if rp_id is None else rp_id, origin)

    def verify_origin(self, origin: str) -> bool:
        """Return True if the origin is accepted by this policy."""
        if self._legacy_allow_list:
            return verify_rp_id(self._rp_id, origin)
        try:
            return _parse_origin(origin) in self._allowed_origins
        except (ValueError, TypeError):
            return False

    def check_origin(self, origin: str) -> None:
        """Raise OriginMismatchError if the origin is not accepted."""
        if not self.verify_origin(origin):
            raise OriginMismatchError(
                "Origin is not in the list of allowed origins."
            )

    def check_rp_id(self, rp_id: str | None = None, origin: str = "") -> None:
        """Raise RpIdMismatchError if the RP ID is unusable for the origin."""
        if not self.verify_rp_id(rp_id, origin):
            raise RpIdMismatchError("RP ID does not match the origin host.")

    def validate(self, rp_id: str | None = None, origin: str = "") -> None:
        """Run origin and RP ID checks using one policy for both phases."""
        self.check_origin(origin)
        self.check_rp_id(rp_id, origin)
