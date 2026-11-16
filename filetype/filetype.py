# -*- coding: utf-8 -*-

from __future__ import absolute_import

from .match import match, match_all
from .registry import registry
from .types import TYPES, Type  # noqa: F401

# Expose supported matchers types
types = TYPES


class MatchResult(object):
    """
    Detailed result of a file type inference.

    In addition to the winning :class:`~filetype.types.base.Type` matcher,
    it exposes a heuristic ``confidence`` in the range [0.0, 1.0] and the
    ``polyglot`` flag, which is True when more than one matcher accepts the
    same magic bytes.

    Attributes:
        kind: winning Type instance, or None when nothing matched.
        mime: MIME type string, or None.
        extension: file extension string, or None.
        confidence: heuristic confidence, 1.0 for a unique match, lower when
            several matchers collide on the same magic bytes.
        polyglot: True if multiple matchers matched the same input.
        matches: ordered list of all matching Type instances.
    """

    def __init__(self, matches):
        self.matches = list(matches)
        self.kind = self.matches[0] if self.matches else None
        self.mime = self.kind.mime if self.kind else None
        self.extension = self.kind.extension if self.kind else None
        self.polyglot = len(self.matches) > 1
        self.confidence = 1.0 if not self.matches else 1.0 / len(self.matches)

    def __repr__(self):
        return ('MatchResult(mime=%r, extension=%r, confidence=%.2f, '
                'polyglot=%r, matches=%d)' % (
                    self.mime, self.extension, self.confidence,
                    self.polyglot, len(self.matches)))

    def __bool__(self):
        return self.kind is not None

    __nonzero__ = __bool__

    def __eq__(self, other):
        if not isinstance(other, MatchResult):
            return NotImplemented
        return self.matches == other.matches

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result


def guess(obj):
    """
    Infers the type of the given input.

    Function is overloaded to accept multiple types in input
    and perform the needed type inference based on it.

    Args:
        obj: path to file, bytes or bytearray.

    Returns:
        The matched type instance. Otherwise None.

    Raises:
        TypeError: if obj is not a supported type.
    """
    return match(obj) if obj else None


def guess_mime(obj):
    """
    Infers the file type of the given input
    and returns its MIME type.

    Args:
        obj: path to file, bytes or bytearray.

    Returns:
        The matched MIME type as string. Otherwise None.

    Raises:
        TypeError: if obj is not a supported type.
    """
    kind = guess(obj)
    return kind.mime if kind else kind


def guess_extension(obj):
    """
    Infers the file type of the given input
    and returns its RFC file extension.

    Args:
        obj: path to file, bytes or bytearray.

    Returns:
        The matched file extension as string. Otherwise None.

    Raises:
        TypeError: if obj is not a supported type.
    """
    kind = guess(obj)
    return kind.extension if kind else kind


def guess_all(obj):
    """
    Infers all the file types compatible with the given input,
    ordered by effective match priority.

    A result with more than one element means the input is a polyglot file:
    several matchers accept its magic bytes.

    Args:
        obj: path to file, bytes or bytearray.

    Returns:
        List of matched Type instances (possibly empty).

    Raises:
        TypeError: if obj is not a supported type.
    """
    return match_all(obj) if obj else []


def guess_info(obj):
    """
    Infers the file type of the given input and returns a detailed
    :class:`MatchResult` with confidence and polyglot information.

    Args:
        obj: path to file, bytes or bytearray.

    Returns:
        MatchResult describing every matcher that accepted the input.

    Raises:
        TypeError: if obj is not a supported type.
    """
    return MatchResult(guess_all(obj))


def guess_mime_info(obj):
    """
    Same as :func:`guess_info`, exposed for MIME-oriented callers.

    Args:
        obj: path to file, bytes or bytearray.

    Returns:
        MatchResult describing every matcher that accepted the input.

    Raises:
        TypeError: if obj is not a supported type.
    """
    return guess_info(obj)


def guess_extension_info(obj):
    """
    Same as :func:`guess_info`, exposed for extension-oriented callers.

    Args:
        obj: path to file, bytes or bytearray.

    Returns:
        MatchResult describing every matcher that accepted the input.

    Raises:
        TypeError: if obj is not a supported type.
    """
    return guess_info(obj)


def get_type(mime=None, ext=None):
    """
    Returns the file type instance searching by
    MIME type or file extension.

    Args:
        ext: file extension string. E.g: jpg, png, mp4, mp3
        mime: MIME string. E.g: image/jpeg, video/mpeg

    Returns:
        The matched file type instance. Otherwise None.
    """
    for kind in types:
        if kind.extension == ext or kind.mime == mime:
            return kind
    return None


def add_type(instance):
    """
    Adds a new type matcher instance to the supported types.

    Args:
        instance: Type inherited instance.

    Returns:
        None
    """
    registry.add_type(instance)


def register_type(instance, priority=0):
    """
    Registers a custom type matcher at runtime.

    Thread-safe. Matchers with a higher ``priority`` are evaluated first and
    therefore override baseline matchers or lower-priority custom matchers
    sharing the same magic bytes, MIME type or extension.

    Re-registering an equivalent matcher (same identity or same MIME and
    extension) updates its priority instead of inserting a duplicate.

    Args:
        instance: Type inherited instance.
        priority: integer priority, higher wins. Defaults to 0.

    Returns:
        The registered matcher instance.
    """
    return registry.add_type(instance, priority=priority)


def unregister_type(instance=None, mime=None, extension=None):
    """
    Removes a previously registered custom matcher.

    Thread-safe. The matcher can be identified by instance, MIME type or
    extension. Baseline matchers shipped with the library are not removable.

    Args:
        instance: exact matcher instance to remove.
        mime: MIME type of the matcher to remove.
        extension: file extension of the matcher to remove.

    Returns:
        The removed matcher instance. Otherwise None.
    """
    return registry.remove_type(
        instance=instance, mime=mime, extension=extension)


def reset_types():
    """
    Removes every custom matcher and restores the baseline matchers.
    """
    registry.reset()


def registered_type(instance, priority=0):
    """
    Context manager registering a matcher for the duration of a ``with``
    block and unregistering it afterwards, even on exceptions.

    Args:
        instance: Type inherited instance.
        priority: integer priority, higher wins. Defaults to 0.
    """
    return registry.registered_type(instance, priority=priority)
