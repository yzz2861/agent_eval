# -*- coding: utf-8 -*-

from __future__ import absolute_import

from .types import ARCHIVE as archive_matchers
from .types import AUDIO as audio_matchers
from .types import APPLICATION as application_matchers
from .types import DOCUMENT as document_matchers
from .types import FONT as font_matchers
from .types import IMAGE as image_matchers
from .types import VIDEO as video_matchers
from .types import TYPES
from .utils import get_bytes


def match(obj, matchers=TYPES, search_window=0, min_match_length=0):
    """
    Matches the given input against the available
    file type matchers.

    Args:
        obj: path to file, bytes or bytearray.
        matchers: list of type matchers to match against.
        search_window: maximum byte offset to scan for a signature.
            Defaults to 0, which only matches at offset 0 (fast path).
            When greater than 0, signatures are located within the
            [0, search_window] offset range, tolerating garbage
            prefixes prepended to the sample.
        min_match_length: minimum number of bytes that must remain
            from a given offset to attempt a match. Offsets leaving
            fewer bytes than this are skipped, avoiding matches on
            truncated signature tails.

    Returns:
        Type instance if type matches. Otherwise None.

    Raises:
        TypeError: if obj is not a supported type.
    """
    buf = get_bytes(obj)

    if search_window > 0:
        return match_with_window(buf, matchers, search_window,
                                 min_match_length)

    for matcher in matchers:
        if matcher.match(buf):
            return matcher

    return None


def match_with_window(buf, matchers, search_window, min_match_length=0):
    """
    Matches the given buffer against the available matchers,
    scanning for signatures at every offset within the given
    search window.

    Args:
        buf: bytearray with the file header signature bytes.
        matchers: list of type matchers to match against.
        search_window: maximum byte offset to scan for a signature.
        min_match_length: minimum number of bytes that must remain
            from a given offset to attempt a match.

    Returns:
        Type instance if type matches. Otherwise None.
    """
    length = len(buf)
    max_offset = min(search_window, length)

    for offset in range(max_offset + 1):
        if length - offset < min_match_length:
            break
        window = buf[offset:]
        for matcher in matchers:
            if matcher.match(window):
                return matcher

    return None


def image_match(obj):
    """
    Matches the given input against the available
    image type matchers.

    Args:
        obj: path to file, bytes or bytearray.

    Returns:
        Type instance if matches. Otherwise None.

    Raises:
        TypeError: if obj is not a supported type.
    """
    return match(obj, image_matchers)


def font_match(obj):
    """
    Matches the given input against the available
    font type matchers.

    Args:
        obj: path to file, bytes or bytearray.

    Returns:
        Type instance if matches. Otherwise None.

    Raises:
        TypeError: if obj is not a supported type.
    """
    return match(obj, font_matchers)


def video_match(obj):
    """
    Matches the given input against the available
    video type matchers.

    Args:
        obj: path to file, bytes or bytearray.

    Returns:
        Type instance if matches. Otherwise None.

    Raises:
        TypeError: if obj is not a supported type.
    """
    return match(obj, video_matchers)


def audio_match(obj):
    """
    Matches the given input against the available
    autio type matchers.

    Args:
        obj: path to file, bytes or bytearray.

    Returns:
        Type instance if matches. Otherwise None.

    Raises:
        TypeError: if obj is not a supported type.
    """
    return match(obj, audio_matchers)


def archive_match(obj):
    """
    Matches the given input against the available
    archive type matchers.

    Args:
        obj: path to file, bytes or bytearray.

    Returns:
        Type instance if matches. Otherwise None.

    Raises:
        TypeError: if obj is not a supported type.
    """
    return match(obj, archive_matchers)


def application_match(obj):
    """
    Matches the given input against the available
    application type matchers.

    Args:
        obj: path to file, bytes or bytearray.

    Returns:
        Type instance if matches. Otherwise None.

    Raises:
        TypeError: if obj is not a supported type.
    """
    return match(obj, application_matchers)


def document_match(obj):
    """
    Matches the given input against the available
    document type matchers.

    Args:
        obj: path to file, bytes or bytearray.

    Returns:
        Type instance if matches. Otherwise None.

    Raises:
        TypeError: if obj is not a supported type.
    """
    return match(obj, document_matchers)
