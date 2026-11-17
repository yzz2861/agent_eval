# -*- coding: utf-8 -*-
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#
#  Author: Mauro Soria

import re

from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

from lib.core.settings import STANDARD_PORTS
from lib.utils.common import lstrip_once


def _origin(value: str) -> tuple[str, str, int | None] | None:
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None

    scheme = parsed.scheme.lower()
    if not scheme or hostname is None:
        return None

    return (
        scheme,
        hostname.lower(),
        port if port is not None else STANDARD_PORTS.get(scheme),
    )


def same_origin(first: str, second: str) -> bool:
    first_origin = _origin(first)
    return first_origin is not None and first_origin == _origin(second)


def same_origin_path(base_url: str, location: str) -> str | None:
    try:
        resolved = urljoin(base_url, location)
    except ValueError:
        return None

    if not same_origin(base_url, resolved):
        return None

    return parse_path(resolved)


def clean_path(path: str, keep_queries: bool = False, keep_fragment: bool = False) -> str:
    if not keep_fragment:
        path = path.split("#")[0]
    if not keep_queries:
        path = path.split("?")[0]

    return path


_PERCENT_ENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")


def _normalize_percent_encoding(path: str) -> str:
    """Normalize percent-encoded triplets without merging distinct resources.

    Encodings of unreserved characters are decoded (e.g. ``%61`` -> ``a``),
    while reserved characters keep their encoding with uppercase hex digits
    (e.g. ``%2f`` -> ``%2F``). This collapses ``%61dmin``/``admin`` and
    ``%7euser``/``~user`` but never turns an encoded slash into a real one.
    """

    def decode_triplet(match: re.Match) -> str:
        character = unquote(match.group(0))
        if (character.isascii() and character.isalnum()) or character in "-._~":
            return character
        return match.group(0).upper()

    return _PERCENT_ENCODED_RE.sub(decode_triplet, path)


def canonical_path(path: str, *, keep_trailing_slash: bool = False) -> str:
    """Return a canonical key for discovery/deduplication of request paths.

    Queries and fragments are dropped, percent-encoding is normalized, the
    path is case-folded and a single trailing slash is removed by default.
    The returned value is only a comparison key: request paths themselves are
    not rewritten, so case- or encoding-sensitive servers keep working.
    """
    path = clean_path(path).lower()
    path = _normalize_percent_encoding(path)

    if not keep_trailing_slash and len(path) > 1:
        path = path.rstrip("/")
        if not path:
            path = "/"

    return path


def canonical_url(url: str, *, keep_trailing_slash: bool = False) -> str:
    """Return a canonical key for an absolute URL or origin-relative path."""
    origin = _origin(url)
    if origin is None:
        return canonical_path(
            parse_path(url), keep_trailing_slash=keep_trailing_slash
        )

    scheme, hostname, port = origin
    origin_key = f"{scheme}://{hostname}"
    if port is not None and port != STANDARD_PORTS.get(scheme):
        origin_key += f":{port}"

    return origin_key + "/" + canonical_path(
        parse_path(url), keep_trailing_slash=keep_trailing_slash
    ).lstrip("/")


def parse_path(value: str) -> str:
    try:
        scheme, url = value.split("//", 1)
        if (
            scheme and (not scheme.endswith(":") or "/" in scheme)
            or url.startswith("/")
        ):
            raise ValueError

        return "/".join(url.split("/")[1:])
    except ValueError:
        return lstrip_once(value, "/")


def ensure_trailing_path_slash(url: str) -> str:
    parsed = urlsplit(url)
    path = parsed.path
    if not path.endswith("/"):
        path += "/"

    return urlunsplit(parsed._replace(path=path))


def append_query_string(value: str, query: str) -> str:
    if not query or "?" in value:
        return value

    path, separator, fragment = value.partition("#")
    value = f"{path}?{query}"
    if separator:
        value += f"#{fragment}"

    return value
