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


def matcher_name(matcher):
    """
    Returns a stable, human readable identifier for a matcher instance.

    The class name is used instead of ``id(matcher)`` so reports produced by
    separate processes can be compared.
    """
    cls = type(matcher)
    module = getattr(cls, '__module__', '')
    name = getattr(cls, '__qualname__', cls.__name__)
    return '%s.%s' % (module, name) if module else name


class MatcherError(object):
    """
    Describes a matcher that raised while inspecting a file prefix.

    The matcher list is deliberately not aborted by ``ranked_matches`` in
    audit mode. Keeping the exception, index and matcher identity makes it
    possible to point at both the affected samples and the registry that
    produced the failure.
    """
    def __init__(self, matcher, index, exception):
        self.matcher = matcher
        self.index = index
        self.rank = index + 1
        self.exception = exception
        self.error = exception
        self.matcher_name = matcher_name(matcher)
        self.error_type = type(exception).__name__
        self.message = str(exception)

    def to_dict(self):
        return {
            'matcher': self.matcher_name,
            'index': self.index,
            'rank': self.rank,
            'error': self.error_type,
            'message': self.message,
        }

    def __repr__(self):
        return '<MatcherError %s at rank %d: %s: %s>' % (
            self.matcher_name, self.rank, self.error_type, self.message
        )


class MatchCandidate(object):
    """
    A matcher that matched a file prefix, together with its registry rank.

    ``index`` is zero based while ``rank`` is the one based matching order
    reported to users.
    """
    def __init__(self, matcher, index):
        self.matcher = matcher
        self.index = index
        self.rank = index + 1
        self.mime = getattr(matcher, 'mime', None)
        self.extension = getattr(matcher, 'extension', None)
        self.matcher_name = matcher_name(matcher)

    @property
    def name(self):
        return self.matcher_name

    def to_dict(self):
        return {
            'type': {
                'mime': self.mime,
                'extension': self.extension,
            },
            'mime': self.mime,
            'extension': self.extension,
            'matcher': self.matcher_name,
            'matcher_name': self.matcher_name,
            'index': self.index,
            'rank': self.rank,
        }

    def __repr__(self):
        return '<MatchCandidate %s (%s) rank=%d>' % (
            self.extension, self.mime, self.rank
        )


class MatchCandidates(list):
    """
    Ordered list of matching candidates.

    This is a normal list so callers can treat it as ``[candidate, ...]``.
    Matcher failures captured while building it are available on ``errors``.
    """
    def __init__(self, candidates=None, errors=None):
        super(MatchCandidates, self).__init__(candidates or [])
        self.errors = list(errors or [])


def ranked_matches(obj, matchers=TYPES, on_error='raise'):
    """
    Matches ``obj`` against every matcher and returns all matches in registry
    order.

    Args:
        obj: path to file, bytes or bytearray.
        matchers: ordered iterable of matchers. Defaults to ``TYPES``.
        on_error: ``'raise'`` propagates matcher exceptions (the historical
            behavior of :func:`match`). ``'record'`` and ``'skip'`` continue
            with the remaining matchers and expose failures through the
            returned object's ``errors`` attribute.

    Returns:
        MatchCandidates: ordered matching candidates. The first item is the
        same matcher :func:`match` would return.
    """
    if on_error not in ('raise', 'record', 'skip'):
        raise ValueError("on_error must be 'raise', 'record' or 'skip'")

    buf = get_bytes(obj)
    candidates = MatchCandidates()

    for index, matcher in enumerate(matchers):
        try:
            matched = matcher.match(buf)
        except Exception as error:
            if on_error == 'raise':
                raise
            candidates.errors.append(MatcherError(matcher, index, error))
            continue

        if matched:
            candidates.append(MatchCandidate(matcher, index))

    return candidates


def match_all(obj, matchers=TYPES, on_error='raise'):
    """
    Returns every match for ``obj`` in registration order.

    This is the diagnostic counterpart of :func:`match`: it does not stop at
    the first match, which makes precedence changes visible.
    """
    return ranked_matches(obj, matchers=matchers, on_error=on_error)


def match_with_rank(obj, matchers=TYPES, on_error='raise'):
    """
    Returns the winning :class:`MatchCandidate`, or ``None``.

    The candidate carries the zero based ``index`` and one based ``rank`` of
    the matcher that won.
    """
    candidates = ranked_matches(obj, matchers=matchers, on_error=on_error)
    return candidates[0] if candidates else None


def match(obj, matchers=TYPES):
    """
    Matches the given input against the available
    file type matchers.

    Args:
        obj: path to file, bytes or bytearray.

    Returns:
        Type instance if type matches. Otherwise None.

    Raises:
        TypeError: if obj is not a supported type.
    """
    buf = get_bytes(obj)

    for matcher in matchers:
        if matcher.match(buf):
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
