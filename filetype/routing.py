# -*- coding: utf-8 -*-

from __future__ import absolute_import

from .types import TYPES, Type
from .utils import get_bytes

# Public routing verdicts.
ALLOW = 'allow'
QUARANTINE = 'quarantine'
NEED_MORE = 'need_more'

# Per-candidate resolution status.
MATCHED = 'matched'
PENDING = 'pending'
ELIMINATED = 'eliminated'


class MagicMatcher(Type):
    """
    A :class:`~filetype.types.Type` matcher that also declares the leading
    signature (magic numbers) it relies on.

    Declaring ``magic`` lets the safe router tell whether an incomplete
    prefix still keeps the matcher in play (pending) or already contradicts
    it (eliminated), without changing how :meth:`match` behaves.

    Args:
        mime: MIME type reported for this kind.
        extension: File extension reported for this kind.
        magic: Leading byte signature. Alternative signatures may be passed
            as a tuple/list of byte strings.
        minimum_bytes: Total prefix length the matcher needs to return a
            trustworthy result. Defaults to the longest magic signature.
    """

    def __init__(self, mime, extension, magic, minimum_bytes=None):
        super(MagicMatcher, self).__init__(mime, extension)
        if isinstance(magic, (bytes, bytearray)):
            magic = (bytes(magic),)
        else:
            magic = tuple(bytes(item) for item in magic)
        self._magic = magic
        self._minimum_bytes = minimum_bytes

    @property
    def magic(self):
        return self._magic

    @property
    def minimum_bytes(self):
        if self._minimum_bytes is not None:
            return self._minimum_bytes
        return max(len(item) for item in self._magic)

    def prefix_compatible(self, buf):
        """
        Returns ``True`` while the available prefix does not contradict any
        of the declared magic signatures.
        """
        for signature in self._magic:
            size = min(len(signature), len(buf))
            if size == 0 or bytearray(buf[:size]) == bytearray(signature[:size]):
                return True
        return False

    def match(self, buf):
        for signature in self._magic:
            if len(buf) >= len(signature) and \
                    bytearray(buf[:len(signature)]) == bytearray(signature):
                return True
        return False


class Candidate(object):
    """
    Resolution snapshot for a single matcher against the current prefix.

    Attributes:
        matcher: The matcher instance being evaluated.
        mime: MIME type of the matcher.
        extension: File extension of the matcher.
        status: One of :data:`MATCHED`, :data:`PENDING`, :data:`ELIMINATED`.
        need_bytes: Additional bytes this pending matcher requires beyond the
            current prefix, or ``None`` when no finite evidence is declared.
    """

    __slots__ = ('matcher', 'mime', 'extension', 'status', 'need_bytes')

    def __init__(self, matcher, status, need_bytes=None):
        self.matcher = matcher
        self.mime = matcher.mime
        self.extension = matcher.extension
        self.status = status
        self.need_bytes = need_bytes

    def to_dict(self):
        return {
            'mime': self.mime,
            'extension': self.extension,
            'status': self.status,
            'need_bytes': self.need_bytes,
        }


class Consumer(object):
    """
    A downstream consumer (e.g. the preview or archive worker) and the set of
    MIME types / extensions it is allowed to decode.

    An empty policy denies everything, keeping an unconfigured consumer on
    the safe side instead of silently accepting unknown content.
    """

    def __init__(self, name, mimes=None, extensions=None):
        self.name = name
        self._mimes = frozenset(mimes or ())
        self._extensions = frozenset(extensions or ())

    @property
    def allowed_mimes(self):
        return tuple(sorted(self._mimes))

    @property
    def allowed_extensions(self):
        return tuple(sorted(self._extensions))

    def permits(self, matcher):
        return (matcher.mime in self._mimes or
                matcher.extension in self._extensions)

    def to_dict(self):
        return {
            'name': self.name,
            'allowed_mimes': self.allowed_mimes,
            'allowed_extensions': self.allowed_extensions,
        }


class RoutingDecision(object):
    """
    The outcome of :func:`route`.

    Attributes:
        verdict: One of :data:`ALLOW`, :data:`QUARANTINE`, :data:`NEED_MORE`.
        reasons: Stable, human-readable explanation strings.
        matched: Candidates whose matcher currently matches the prefix.
        pending: Candidates that still need more bytes to decide.
        eliminated: Candidates already contradicted by the prefix.
        candidates: Every candidate, sorted deterministically.
        need_bytes: Additional bytes required to resolve every pending
            candidate, or ``None`` if no finite evidence can be derived.
        consumers: The consumer policies considered during routing.
        allowed_types: MIME types and extensions reachable by the matchers.
        prefix_length: Number of prefix bytes the decision was based on.
    """

    __slots__ = ('verdict', 'reasons', 'matched', 'pending', 'eliminated',
                 'candidates', 'need_bytes', 'consumers', 'allowed_types',
                 'prefix_length')

    def __init__(self, verdict, reasons, matched, pending, eliminated,
                 candidates, need_bytes, consumers, allowed_types,
                 prefix_length):
        self.verdict = verdict
        self.reasons = tuple(reasons)
        self.matched = tuple(matched)
        self.pending = tuple(pending)
        self.eliminated = tuple(eliminated)
        self.candidates = tuple(candidates)
        self.need_bytes = need_bytes
        self.consumers = tuple(consumers)
        self.allowed_types = allowed_types
        self.prefix_length = prefix_length

    @property
    def primary(self):
        """The uniquely matched matcher, otherwise ``None``."""
        if len(self.matched) == 1:
            return self.matched[0].matcher
        return None

    def to_dict(self):
        return {
            'verdict': self.verdict,
            'reasons': list(self.reasons),
            'matched': [item.to_dict() for item in self.matched],
            'pending': [item.to_dict() for item in self.pending],
            'eliminated': [item.to_dict() for item in self.eliminated],
            'candidates': [item.to_dict() for item in self.candidates],
            'need_bytes': self.need_bytes,
            'prefix_length': self.prefix_length,
            'consumers': [item.to_dict() for item in self.consumers],
            'allowed_types': self.allowed_types,
        }


def _candidate_for(matcher, buf):
    if matcher.match(buf):
        return Candidate(matcher, MATCHED)

    if isinstance(matcher, MagicMatcher):
        if not matcher.prefix_compatible(buf):
            return Candidate(matcher, ELIMINATED)
        need = max(matcher.minimum_bytes - len(buf), 1)
        return Candidate(matcher, PENDING, need)

    # A plain Type only exposes a boolean match(): it cannot be eliminated
    # from a prefix alone, so it stays pending with no finite evidence.
    return Candidate(matcher, PENDING, None)


def _sorted(candidates):
    return sorted(
        candidates,
        key=lambda item: (item.mime or '', item.extension or ''))


def _next_evidence(pending):
    needs = [item.need_bytes for item in pending
             if item.need_bytes is not None]
    if not needs:
        return None
    return max(needs)


def collect_candidates(obj, matchers=TYPES):
    """
    Evaluates every matcher against the (possibly incomplete) prefix and
    returns all candidates instead of stopping at the first match.

    Args:
        obj: path to file, bytes, bytearray, memoryview or file-like object.
        matchers: Iterable of matcher instances. Defaults to the built-ins.

    Returns:
        Tuple ``(matched, pending, eliminated, candidates)`` with each group
        sorted deterministically so the result does not depend on matcher
        registration order.
    """
    buf = get_bytes(obj)
    candidates = _sorted([_candidate_for(matcher, buf)
                          for matcher in matchers])

    matched = [item for item in candidates if item.status == MATCHED]
    pending = [item for item in candidates if item.status == PENDING]
    eliminated = [item for item in candidates if item.status == ELIMINATED]
    return tuple(matched), tuple(pending), tuple(eliminated), tuple(candidates)


def allowed_types(matchers=TYPES):
    """
    Summarizes every MIME type and extension reachable through the matchers.
    """
    mimes = sorted(set(matcher.mime for matcher in matchers))
    extensions = sorted(set(matcher.extension for matcher in matchers))
    return {'mimes': tuple(mimes), 'extensions': tuple(extensions)}


def _permitted(primary, consumers):
    return [consumer for consumer in consumers
            if consumer.permits(primary.matcher)]


def route(obj, consumers=None, matchers=TYPES, final=False):
    """
    Independently callable safe routing decision for an upload prefix.

    Unlike :func:`filetype.guess`, this never stops at the first matching
    decoder. It aggregates every candidate, tracks the minimum evidence still
    required and enforces each consumer's allowed types.

    Args:
        obj: path to file, bytes, bytearray, memoryview or file-like object.
        consumers: Iterable of :class:`Consumer` policies. When empty the
            decision only reports type reachability without policy filtering.
        matchers: Iterable of matcher instances. Defaults to the built-ins.
        final: When ``True`` the stream is considered complete, so pending
            candidates can no longer rescue an undecidable prefix.

    Returns:
        A :class:`RoutingDecision` whose ``verdict`` is :data:`ALLOW`,
        :data:`QUARANTINE` or :data:`NEED_MORE`.
    """
    consumers = tuple(consumers or ())
    buf = get_bytes(obj)
    prefix_length = len(buf)
    matched, pending, eliminated, candidates = collect_candidates(
        buf, matchers)
    need_bytes = _next_evidence(pending)
    reachable = allowed_types(matchers)
    reasons = []

    if len(matched) > 1:
        verdict = QUARANTINE
        reasons.append('ambiguous signature: %d matchers match the same '
                       'prefix' % len(matched))
    elif len(matched) == 1:
        primary = matched[0]
        permitted = _permitted(primary, consumers)
        if consumers and not permitted:
            verdict = QUARANTINE
            reasons.append('matched type %s is not allowed by any consumer'
                           % primary.mime)
        else:
            verdict = ALLOW
            if consumers:
                reasons.append('unique match %s accepted by %d consumer(s)'
                               % (primary.mime, len(permitted)))
            else:
                reasons.append('unique match %s' % primary.mime)
            if pending:
                reasons.append('%d pending candidate(s) remain unresolved'
                               % len(pending))
    else:
        if final:
            verdict = QUARANTINE
            reasons.append('stream ended with %d unresolved candidate(s)'
                           % len(pending))
        elif not pending:
            verdict = QUARANTINE
            reasons.append('no matching signature and no candidate can still '
                           'match this prefix')
        else:
            verdict = NEED_MORE
            reasons.append('no match yet; %d candidate(s) still possible'
                           % len(pending))
            if need_bytes is None:
                reasons.append('pending matchers declare no finite evidence '
                               'requirement')
            else:
                reasons.append('read %d more byte(s) to reach a decision'
                               % need_bytes)

    return RoutingDecision(
        verdict=verdict,
        reasons=reasons,
        matched=matched,
        pending=pending,
        eliminated=eliminated,
        candidates=candidates,
        need_bytes=need_bytes,
        consumers=consumers,
        allowed_types=reachable,
        prefix_length=prefix_length,
    )
